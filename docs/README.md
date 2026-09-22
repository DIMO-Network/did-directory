# docs

| File | What it is |
|---|---|
| `eras-tags-and-grants.html` | Visual explainer for the controller-of-record and delegation model: today's on-chain permission stack next to the new one, where records live, coverage over time, narrowing chains, token issuance, and the Avis case study. Open it in a browser. |

Design spec: `superpowers/specs/2026-09-16-dimo-orgs-fleets-delegation-design.md`. Org host plan: `superpowers/plans/2026-09-22-org-host-plan.md`.

## Org host

`cmd/org-host` serves org repositories (plan §3). Each org's records live in a hash-chained commit log signed by its `#dimo_org` key; `pkg/repo` defines the commit and verifies a whole log offline against that key.

Run it against Postgres with a sealed-key master key, or with no `DATABASE_URL` for an in-memory store:

```
openssl rand -base64 32   # MASTER_KEY
DATABASE_URL=postgres://... MASTER_KEY=... IDENTITY_JWKS_URL=http://localhost:8080/signin/keys go run ./cmd/org-host -settings /dev/null
```

Every route but `/health` takes a `Bearer` identity token (RS256, `sub` = DID) verified against the configured JWKS: dauth's `/signin/keys`, which `dimocli signin` obtains a token from. `DIRECTORY_URL` names the DID directory the host reads control state from; `ISSUER_DIDS` lists who may call `/authorize` (dauth) and `ADMIN_DIDS` who may set party attributes (DIMO).

Under `/orgs` the org itself may write anything to its own repository, subject to the same approvals as anyone. Anyone else is a member only through a live `network.dimo.org.role` record, and each write takes the ability plan §3.2 names over the record's scope: `delegation:create` plus the abilities handed out for a delegation, `org:members` plus the abilities handed out for a role, `tag:write` for tags and memberships (plus, for a membership, the abilities of every delegation over the tag, spec §9.2), `org:admin` for control openings and `delegation:create` over the vehicle for custody. Delegations and roles pass `delegation.CheckCommit` under the policy the member's role names in `constraints.policy` (`default`, or `rental-booking` for a booking service); a write the policy wants a second approval for answers `202 {pending, uri, reasons}` and commits when somebody else approves it: the org, or a member holding `delegation:create` (`org:members` for a role, `tag:write` for a membership) over its scope. An org's first role therefore carries no live abilities, and its booking role waits for that admin. Reads take any live role; the openings and the commit log take `org:admin`.

| Route | What it does |
|---|---|
| `POST /orgs/:org` | Registers the org on this host and mints its `#dimo_org` key (or takes one as `{"privateKey": <base64 PKCS#8>}`). Only the org itself may call it. Returns the did:key to publish with `dimocli update --org-key`. |
| `GET /orgs/:org` | The org's key and log head. |
| `PUT /orgs/:org/:collection/:rkey` | Creates or updates a record. `POST /orgs/:org/:collection` does the same under a fresh TID. |
| `DELETE /orgs/:org/:collection/:rkey` | Tombstones a record: by a principal its `revocableBy` names, or a member of one holding `delegation:create` (`org:members` for a role) over its scope. |
| `GET /orgs/:org/pending` | Writes awaiting approval. `POST /orgs/:org/pending/:id/approve` commits one as the caller's approval; the author and the recipient cannot. `DELETE /orgs/:org/pending/:id` withdraws one. |
| `POST /orgs/:org/revoke-authored-by` | `{member, since}` lists the live records whose current version the member committed after `since`; with `uris` it tombstones that reviewed set as one batch, every tombstone checked as a `DELETE` first. |
| `GET /orgs/:org/:collection[/:rkey]` | Lists live records, or reads one (a tombstoned record answers 410 with its last body and who revoked it). |
| `GET /orgs/:org/commits?after=&limit=` | The commit log, for sync and offline verification with `repo.VerifyLog`. |
| `POST /authorize` | For the issuer: `{uri, caller, clientId?, vehicle, abilities}` runs `delegation.Evaluator.Authorize` at the host clock and returns the coverage plus `at`, or 403 with a `code` (`not_covered`, `exclusive_hold` with the `suspended` abilities, `unauthorized`, `revoked`, `not_valid`, ...) and 404 for a record that is not here. `at` in the request is refused in v1. |
| `PUT /parties/:did` | Admins record `{kind: person\|org, operator}` for a DID (plan §1 decision E). `GET` reads it. An org with no row is an org and not an operator; any other unlisted DID is nobody in particular. |

### Booking SDK

`pkg/agreement/booking` is what an operator's booking service links (plan §5, decision F). `Client.Sync(ctx, agreement, catalog, now)` compiles the agreement with `agreement.Compile` and brings the operator's repository into line with it: custody legs under `bookingID:<leg start>`, every compiled grant under its stable key, and a tombstone for every key `agreement.Keys` lists that the compilation no longer produces (custody after the return, roadside once the incident closes, everything after a cancellation before pickup). It is stateless and idempotent, writes as the booking service with the identity token its role was written to, and returns the host's answer per write; a write the host parks for approval is reported as `OpPending` rather than as an error. The host never learns what a booking is.

Tests run against the in-memory store by default; `make test-postgres` also runs them against a local `org_host_test` database.
