# docs

| File | What it is |
|---|---|
| [2026-09-23-spec-compliance-review.md](2026-09-23-spec-compliance-review.md) | Cross-repository spec review: authorization and history findings, reproduction results, scope deviations and validation limits. |
| [2026-10-01-identity-explorer.md](2026-10-01-identity-explorer.md) | What replaces the identity-api: the directory as it is for public data, the org host read with each caller's own token for private data, and the routes to add first. |
| `eras-tags-and-grants.html` | Visual explainer for the controller-of-record and delegation model: today's on-chain permission stack next to the new one, where records live, coverage over time, narrowing chains, token issuance, and the RentalCo case study. Open it in a browser. |

Design spec: `superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md`. Org host plan: `superpowers/plans/2026-09-22-org-host-plan.md`.

## Org host

`cmd/org-host` serves org repositories (plan §3). Each org's records live in a hash-chained commit log signed by its `#dimo_org` key; `pkg/repo` defines the commit and verifies a whole log offline against that key.

Run it against Postgres with a sealed-key master key, or with no `DATABASE_URL` for an in-memory store:

```
openssl rand -base64 32   # MASTER_KEY
DATABASE_URL=postgres://... MASTER_KEY=... IDENTITY_JWKS_URL=http://localhost:8080/signin/keys \
  IDENTITY_ISSUER=http://localhost:8080/signin IDENTITY_AUDIENCE=http://localhost:8081 \
  go run ./cmd/org-host -settings /dev/null
```

Every route but `/health` takes a `Bearer` identity token (RS256, `sub` = DID) verified against the configured JWKS: dauth's `/signin/keys`, which `dimocli signin --audience <host URL>` obtains a token from. The token must carry `IDENTITY_ISSUER` as `iss` and name `IDENTITY_AUDIENCE`, the host's own URL, in `aud`; a token a member signed in with for any other service is refused. `DIRECTORY_URL` names the DID directory the host reads control state from; `ISSUER_DIDS` lists who may call `/authorize` (dauth) and `ADMIN_DIDS` who may set party attributes (DIMO).

`IDENTITY_AUDIENCE` and `PUBLIC_URL` must be plain http(s) URLs without a trailing `/`, userinfo, query or fragment, or the host refuses to start. The host URL, a token's `aud` and a DID's `#dimo_org_host` are compared after one normalisation (scheme and host lowercased, default port and trailing slash dropped). Every accepted DPoP proof is remembered until it expires, in the `dpop_proofs` table when there is a database, so a proof one replica accepted is refused by the others; one caller DID may hold `DPOP_MAX_PROOFS_PER_SUBJECT` (10000) live proofs, past which it alone gets 429 (`ISSUER_DIDS` are not capped).

The host fetches `IDENTITY_JWKS_URL` again every five minutes whatever the requests name, replacing its key set, so a key dauth removes stops verifying here within five minutes; a token naming a key id it does not hold triggers a fetch at most once a minute. Fetches are single-flight, give up after five seconds, and a failed one keeps the keys the host had. When rotating dauth's signing keys, add one more step after removing the old key: **restart or refresh every verifier** (each org host replica, accounts, anything else caching dauth's JWKS). That is the step that matters for a compromised key; waiting out the five minutes is enough only for a routine rotation.

Under `/orgs` the org itself may write anything to its own repository, subject to the same approvals as anyone. Anyone else is a member only through a live `network.dimo.org.role` record, and each write takes the ability plan §3.2 names over the record's scope: `delegation:create` plus the abilities handed out for a delegation, `org:members` plus the abilities handed out for a role, `tag:write` for tags and memberships (plus, for a membership, the abilities of every delegation over the tag, spec §9.2), `org:admin` for control openings and `delegation:create` over the vehicle for custody. Delegations and roles pass `delegation.CheckCommit` under the policy the member's role names in `constraints.policy` (`default`, or `rental-booking` for a booking service); a write the policy wants a second approval for answers `202 {pending, uri, reasons}` and commits when somebody else approves it: the org, or a member holding `delegation:create` (`org:members` for a role, `tag:write` for a membership) over its scope. An org's first role therefore carries no live abilities, and its booking role waits for that admin. Reads take any live role; the openings and the commit log take `org:admin`.

| Route | What it does |
|---|---|
| `POST /orgs/:org` | Registers the org on this host and mints its `#dimo_org` key (or, under the local signer, takes one as `{"privateKey": <base64 PKCS#8>}`). Only the org itself may call it, with an `approve` token, and only once its DID names this host as `#dimo_org_host`. Returns the did:key to publish with `dimocli update --org-key`; `dimocli create --org-host` does the whole round (create, sign in, register, publish). A register is charged only once it will make a key, so one refused (403), malformed (400) or for an org already here (409) spends nothing; then per caller (`REGISTER_RATE_LIMIT_PER_CALLER_PER_MINUTE`, 3), against a daily cap on new orgs counted across replicas (`ORG_REGISTER_MAX_PER_DAY`, 200, logged at error level when hit) and host-wide (`REGISTER_RATE_LIMIT_PER_MINUTE`, 10): 429 with Retry-After. A KMS register that should be retried answers 503. |
| `GET /orgs/:org` | The org's key, to anyone signed in; its log head too, to the org and its members. |
| `PUT /orgs/:org/:collection/:rkey` | Creates or updates a record. `POST /orgs/:org/:collection` does the same under a fresh TID. |
| `DELETE /orgs/:org/:collection/:rkey` | Tombstones a record: by a principal its `revocableBy` names, or a member of one holding `delegation:create` (`org:members` for a role) over its scope. |
| `GET /orgs/:org/pending` | Writes awaiting approval. `POST /orgs/:org/pending/:id/approve` commits one as the caller's approval; the author and the recipient cannot. A pending write the caller could neither see nor approve answers 404, as an unknown id does. `DELETE /orgs/:org/pending/:id` withdraws one. |
| `POST /orgs/:org/revoke-authored-by` | `{member, since}` lists the live records whose current version the member committed after `since`; with `uris` it tombstones that reviewed set as one batch, every tombstone checked as a `DELETE` first. |
| `GET /orgs/:org/:collection[/:rkey]` | Lists live records, or reads one (a tombstoned record answers 410 with its last body and who revoked it). |
| `GET /orgs/:org/delegations/:rkey/proof?vehicle=` | The §11.3 coverage proof for one delegation over one vehicle, evaluated now: for the delegation's recipient or the org. Verify it offline with `pkg/proof.Verify` or `dimocli verify-proof`. |
| `GET /orgs/:org/delegations/:rkey/descendants?vehicle=` | Every live delegation below this one, across the host's repositories, each resolved over the vehicle or listed with its refusal code (§9.3): for the org. |
| `GET /orgs/:org/commits?after=&limit=` | The commit log, for sync and offline verification with `repo.VerifyLog`. |
| `POST /authorize` | For the issuer: `{uri, caller, clientId?, vehicle, abilities}` runs `delegation.Evaluator.Authorize` at the host clock and returns the coverage plus `at`, or 403 with a `code` (`not_covered`, `exclusive_hold` with the `suspended` abilities, `unauthorized`, `revoked`, `not_valid`, ...) and 404 for a record that is not here. `at` in the request is refused in v1. |
| `PUT /parties/:did` | Admins record `{kind: person\|org, operator}` for a DID (plan §1 decision E). `GET` reads it. An org with no row is an org and not an operator; any other unlisted DID is nobody in particular. |

### Booking SDK

`pkg/agreement/booking` is what an operator's booking service links (plan §5, decision F). `Client.Sync(ctx, agreement, catalog, now)` compiles the agreement with `agreement.Compile` and brings the operator's repository into line with it: custody legs under `bookingID:<leg start>`, every compiled grant under its stable key, and a tombstone for every key `agreement.Keys` lists that the compilation no longer produces (custody after the return, roadside once the incident closes, everything after a cancellation before pickup). It is stateless and idempotent, writes as the booking service with the identity token its role was written to, and returns the host's answer per write; a write the host parks for approval is reported as `OpPending` rather than as an error. The host never learns what a booking is.

Tests run against the in-memory store by default; `make test-postgres` also runs them against a local `org_host_test` database.

## End-to-end demo

The DID directory (`cmd/did-directory`) refuses to start without `DATABASE_URL` unless `ALLOW_MEMORY_STORE=true`, so a missing database in a deployment is a crash and not a silent in-memory log; the demo scripts set it. `scripts/demo.sh` runs the whole model on one machine: it builds and starts the directory, the org host, dauth and dq (from sibling checkouts, `DAUTH_DIR` and `DQ_DIR`, default `../dauth` and `../dq`) in memory, then walks the RentalCo story of spec §13.1 and the consumer case of §13.3 with a token from dauth's `/exchange` at every step: an org and its fleet, staff roles and a two-person approval, three partner grants including one redelegated through a second repository, a booking compiled by `dimocli booking` through pickup, breakdown and return, a sale by `dimocli transfer`, the buyer's consent, the same car's telemetry queried through dq with `dimocli query` under three grants (the renter's, the insurer's from RentalCo, the insurer's from the buyer), each getting the slice its windows allow, and a coverage proof verified by `dimocli verify-proof` after the host has been stopped. dq's data comes from `cmd/dq-seed` in the dq repo, which plays din for an hour of readings. It needs `go` with cgo (dq embeds DuckDB), `jq`, `curl` and `openssl`, and ports 3000 and 8080 to 8082 free (`DQ_PORT`, `DIRECTORY_PORT`, `ORG_HOST_PORT`, `DAUTH_PORT` move them).

```
./scripts/demo.sh                 # straight through, about 90 seconds
DEMO_PRESENT=1 ./scripts/demo.sh  # for a room: one step per screen, a keypress between steps and before the key moments
```

DIDs are shown by name (RentalCo, car-1, Renter) throughout; the closing summary lists the real identifiers. In presenter mode a token prints as one line per grant: abilities, window, chain.

`dimocli create --org` makes a secp256k1 root (the type of a Turnkey org root) when the key stays in the keystore. A transfer to a custody key the new controller supplies takes their acceptance: `dimocli custody-proof --car <car> --to <them> --key-file <file> [--generate]` signs `DIMO custody acceptance v1\nCar: <car>\nTo: <them>\nEra: <next era>` with that key, and the seller passes `--new-custody-key` and `--new-custody-proof` to `dimocli transfer`, which checks it, and that `--to` is a live DID, before signing.

The `dimocli` commands it uses beyond DID operations: `signin` (an identity token from dauth), `exchange` (sign in, DPoP-prove the DID's key with its `#signing` key, mint an access token for one delegation over one vehicle; `--claims` prints what the token carries, `--client` attests an app with an assertion signed by the app's key and bound to the caller's DPoP key), `query` (mint as `exchange` does, then send a GraphQL query to dq with the token and a DPoP proof for the request), `booking` (sync an agreement JSON to the operator's host as the booking service, under `agreement.RentalCatalog`) and `verify-proof` (check a fetched coverage proof against the directory's `#dimo_org` keys and era log).
