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
DATABASE_URL=postgres://... MASTER_KEY=... IDENTITY_JWKS_URL=http://localhost:3000/siwe/keys go run ./cmd/org-host -settings /dev/null
```

Every route but `/health` takes a `Bearer` identity token (RS256, `sub` = DID) verified against the configured JWKS. `DIRECTORY_URL` names the DID directory the host reads control state from; `ISSUER_DIDS` lists who may call `/authorize` (dauth) and `ADMIN_DIDS` who may set party attributes (DIMO).

| Route | What it does |
|---|---|
| `POST /orgs/:org` | Registers the org on this host and mints its `#dimo_org` key (or takes one as `{"privateKey": <base64 PKCS#8>}`). Only the org itself may call it. Returns the did:key to publish with `dimocli update --org-key`. |
| `GET /orgs/:org` | The org's key and log head. |
| `PUT /orgs/:org/:collection/:rkey` | Creates or updates a record. `POST /orgs/:org/:collection` does the same under a fresh TID. |
| `DELETE /orgs/:org/:collection/:rkey` | Tombstones a record. |
| `GET /orgs/:org/:collection[/:rkey]` | Lists live records, or reads one (a tombstoned record answers 410 with its last body and who revoked it). |
| `GET /orgs/:org/commits?after=&limit=` | The commit log, for sync and offline verification with `repo.VerifyLog`. |
| `POST /authorize` | For the issuer: `{uri, caller, clientId?, vehicle, abilities}` runs `delegation.Evaluator.Authorize` at the host clock and returns the coverage plus `at`, or 403 with a `code` (`not_covered`, `exclusive_hold` with the `suspended` abilities, `unauthorized`, `revoked`, `not_valid`, ...) and 404 for a record that is not here. `at` in the request is refused in v1. |
| `PUT /parties/:did` | Admins record `{kind: person\|org, operator}` for a DID (plan §1 decision E). `GET` reads it. An org with no row is an org and not an operator; any other unlisted DID is nobody in particular. |

Tests run against the in-memory store by default; `make test-postgres` also runs them against a local `org_host_test` database.
