# Org host plan

**Date:** 2026-09-22
**Status:** Decisions settled with Dylan 2026-09-22 (§1). Replaces the lost `docs/org-store-plan.md`.
**Spec:** `../specs/2026-09-16-dimo-orgs-fleets-delegation-design.md` (§6, §7, §9, §11, §12 in particular; decisions in §16 and §19).

The org host is the service that holds every org's private records and is the only thing that writes them. Nothing in the delegation model runs end to end without it: `pkg/delegation` is a pure evaluator behind a `Resolver` interface, `pkg/agreement` is a pure compiler, and until 2026-09-22 the only runnable flow was the SACD path, which is now gone.

## 1. Decisions (settled 2026-09-22, recorded in spec §19)

| # | Question | Decision |
|---|---|---|
| A | Who runs the evaluator? | **The org host.** It runs `delegation.Evaluator` against its own database and exposes `POST /authorize`; dauth calls that once and mints. The split is "dauth authenticates, the org host authorizes". The host already has to run the role checks to gate its own writes, so a separate evaluator in dauth would be the same rule in two processes. Reversible: the request and response are `Evaluator.Authorize`'s signature and `Coverage`, so either service could host the call. What (2) protects that (1) would not: control openings never leave the host except inside a coverage proof, which is what lets a self-hosted org answer for itself later. |
| B | Member authentication for writes | **A dauth-issued identity token** with `sub` = member DID. One sign-in for the platform; the host never sees a key. |
| C | Commit signing in v1 | **A host-held org signing key**, encrypted at rest, behind a `Signer` interface. Turnkey is too heavy for demo-class development and is a swap later. The org DID document carries the public half as `#dimo_org`. |
| D | Second approval | **A protocol-level record fact, not a vendor feature.** A write that `CheckCommit` flags lands as pending; a second member holding the same authority approves; the commit carries `approvedBy` and the evaluator reads that field. Turnkey or any other signer policy is only a way of collecting the second signature and changes nothing the evaluator sees. |
| E | Party attributes | **A DIMO-administered table** of `{kind, operator}` per DID. It is DIMO's say-so and a table is honest about that. Can become a record in a DIMO-authority repository later without changing consumers. |
| F | Who compiles agreements? | **The booking service, client side**, as spec §12 already says. The host stays generic: it never learns what a booking is. `pkg/agreement` is an SDK the operator links; it posts plain delegation records under a constrained booking role, and the role constraints bound what it may write. Custody periods are still host records, because the evaluator narrows by them. The agreement itself stays with the operator; `terms` on every grant hashes the governing contract for disputes. |
| G | Where the code lives | **This repo, `cmd/org-host`, own database.** A separate service; repo placement is convenience until a second consumer of `pkg/delegation` exists. |

## 2. Scope of v1

**In:** one host instance serving every org; records, tags, memberships, roles and custody periods as signed hash-chained commits; write-time checks; two-person approval; `/authorize` for dauth; coverage proofs; descendants listing for consent; tombstones and `revokeAuthoredBy`; membership growth checks.

**Out, deferred on 2026-09-21:** the `ORG_COVERAGE` stream and coverage index, fleet tokens and `coverageRef`, the dq fleet query. Also out: self-hosting, Turnkey, countersignatures, lender notification, the MST, and any knowledge of agreements or catalogs (decision F). None of these change the record model.

## 3. Components

### 3.1 Repository

One repository per org DID. A repository is an append-only commit log:

```
commit {
  seq, prev (hash of previous commit), rev (TID),
  op: create | update | tombstone,
  collection, rkey, record (canonical JSON or CBOR),
  committedBy (member DID the host authenticated, "" for the org itself),
  approvedBy [DID], committedAt,
  sig (over everything above, by the org's #dimo_org key)
}
```

The hash chain is the v1 stand-in for the MST (spec §6.2). `committedAt` is the host clock and is what every `Stored.CommittedAt` and `Membership.CommittedAt` reads. Records are addressed as `at://<orgDID>/<collection>/<rkey>`; every rkey passes `delegation.ValidateRKey`.

As built (step 2): the commit also carries `did`, the org, inside the signature, so a commit cannot be replayed into another repository even if two orgs were published under one key. The record is stored as the canonical JSON that was signed (sorted keys, no whitespace, numbers verbatim) and only derived into jsonb for queries, because a signature has to be checked against the bytes it was made over and jsonb does not give those back. A commit's CID is the sha2-256 multihash of the signed commit, as the directory does for operations; `prev` names it. `committedAt` is UTC at microsecond precision so a timestamptz round trip does not change the signed bytes. `repo.VerifyLog` replays a whole log offline against `#dimo_org`.

Collections, all under the org's authority:

| Collection | rkey | Record | Notes |
|---|---|---|---|
| `network.dimo.delegation` | TID, or a compiled grant key | `delegation.Record` | |
| `network.dimo.org.role` | TID | `delegation.Record` with `Type = role` | |
| `network.dimo.org.tag` | slug | `{name, description}` | |
| `network.dimo.org.tagMembership` | TID | `{tag, vehicle, joinedAt, leftAt?}` | one record per interval; `createdBy` is the commit's `committedBy` |
| `network.dimo.org.vehicleControl` | vehicle DID | `control.Opening` | never leaves the host except inside a coverage proof |
| `network.dimo.org.custody` | TID | `delegation.CustodyPeriod` | written by the booking service under its role, or synced from a device |

Party attributes are not a collection: they live in a host-level table keyed by DID (decision E).

### 3.2 Write path

Every write is `PUT /orgs/:org/:collection/:rkey` or `DELETE` for a tombstone, with a member identity token (decision B).

1. **Authenticate** the token; `committedBy` = its `sub`. A write by the org's own service DID is `committedBy = ""`.
2. **Resolve roles.** `Roles(org, member)` at now. No live role covering the write's scope with the ability the write needs (`delegation:create`, `tag:write`, `org:members`, `org:admin`) is refused.
3. **Check the record.** For delegations and roles, `delegation.CheckCommit(rec, CommitContext{From: party(org), CoveredVehicles: n, Role: role, CommittedBy: member, Approved: hasApproval, Policy: policyFor(org, role)})`. The policy is chosen per org and per role, so a booking role commits under `agreement.CommitPolicy()` without the host knowing what a booking is. For memberships, `CheckMembershipGrowth` over every delegation covering the tag, plus the §9.2 author-authority check.
4. **Approval.** If `CheckCommit` returns `ErrApprovalRequired`, the write lands as **pending** with its reasons (`ApprovalReasons`). A second member with the same authority calls `POST /orgs/:org/pending/:id/approve`; the host re-runs step 3 with `Approved: true` and commits with `approvedBy`. The author cannot approve their own write.
5. **Commit.** Sign, append, return the URI, rev and CID. A `PUT` to an existing rkey is an update commit, which is how a booking service upserts a compiled grant under its stable key; it tombstones grants its next compilation no longer produces.

Records are stored with `createdBy` exactly as sent. The evaluator refuses a record whose `createdBy` contradicts `committedBy`, so the host should reject that at write time too, with a clear message, rather than let it land and fail later.

As built (step 4), what each write takes, all resolved through `Evaluator.RolesCovering`, which is the evaluator's own `hasRole`, so a write the host accepts is one evaluation honours:

| Write | Needs, over the record's scope |
|---|---|
| delegation | `delegation:create` plus every ability the record hands out (`delegation.AuthoringNeed`) |
| role | `org:members` plus every ability the role hands out. The evaluator now checks this too (`roleActive`): a member-written role is only a role if its author held that, and a role to oneself needs a second approval, so a host bug cannot mint authority. |
| tag | `tag:write` over the tag |
| tagMembership | `tag:write` over the tag, then `tag:write` plus D's abilities for every live delegation D over the tag (§9.2, `delegation.MembershipNeed`); a write some D would ignore is refused naming those D. |
| vehicleControl | `org:admin` over the vehicle, or the org itself |
| custody | `delegation:create` over the vehicle: custody narrows grants host-wide (§7), so it takes the same authority as a grant |

**The policy is per role, not per org.** A role names its profile in `constraints.policy` (`RoleConstraints.Policy`); the host holds a registry (`orghost.Policies`, the binary registers `agreement.CommitPolicy()` under its name) and refuses a role naming a profile it does not know. Naming one makes the constraints present, so a booking role also sets `allowExclusive`. The `policy_name` column on `orgs` in §4 was not built. A member holding several roles may commit under any one of them; when none passes, an approval requirement from any role wins over a refusal, since it is the more useful answer.

**The org's own writes park like anyone else's.** The second signature is a record fact (decision D), so nothing depends on who holds the org key or on a signer with its own policy; the blast-radius rules of spec §7 bind the org's service DID too. What makes that possible is **what an approver must hold: the ability that manages records of that kind over the scope** (`delegation:create`, `org:members` for a role, `tag:write` for a membership), not everything the record hands out. The author already holds those, or is the org. The evaluator's `approvedByAnother` applies the same rule. Requiring the approver to hold what a role hands out, as first built, made an org's first writes impossible to approve: before the first role nobody holds anything. Bootstrap is therefore: the org writes an admin role with no live abilities, which commits directly, and every later write the policy flags, the booking role included, waits for that admin. The org may approve a member's write and a member may approve the org's; nobody approves their own.

**Approval** re-runs steps 2 and 3 at approval time with `Approved: true`, so the author must still hold their authority then, which is what evaluation checks at the commit time. The approver must be neither the author nor the recipient. A pending write answers 202 with `{pending, uri, reasons}`; `GET /orgs/:org/pending` lists them for any member; `DELETE /orgs/:org/pending/:id` withdraws one, for its author or the org. Membership growth is counted only when the write adds a vehicle to the tag: re-writing a member's interval, or an interval that has already ended, grows nothing.

### 3.3 Read path for the issuer

`POST /authorize` with `{uri, caller, clientId, vehicle, abilities, at?}` from dauth only (service-to-service auth). The host runs `Evaluator.Authorize` against a `Resolver` backed by its own database and the directory (`pkg/client.Control` for `ControlState`), and returns `delegation.Coverage` or a typed error (`not covered`, `exclusive hold` with the abilities, `unauthorized`). `at` defaults to now and is only honoured for callers allowed to ask about the past, which in v1 is nobody.

The `Resolver` implementation is the bulk of the host's read code:

| Method | Backed by |
|---|---|
| `Record` | records table, any org, by URI |
| `Memberships`, `TagSize` | tagMembership, indexed on `(tag, vehicle)` and `(tag, joinedAt, leftAt)` |
| `Custody` | custody, indexed on `(vehicle, holder)` |
| `Roles` | role records including tombstoned, indexed on `(org, to)` |
| `ControlState` | directory `GET /:did/control`, cached briefly |
| `Opening` | vehicleControl in the controller's repository |
| `Party` | party table |
| `Exclusives` | delegations with `exclusive` over the vehicle, live at `at`; `Since` from validity start or commit time |

As built (step 3): `internal/orghost.Resolver` reads records from any repository on this host, so a chain from one org through another resolves as long as both live here. `Custody` and `Exclusives` are likewise host-wide, found by `(vehicle, holder)` and by `covers.vehicle`, plus `covers.tag` for a tag the vehicle has a raw live membership in at `at`; an exclusive claim whose coverage is `inherit` is not found, since finding it means evaluating its chain, which is what the deferred coverage index was for. Control state comes from the directory through `pkg/client.Control`, cached 30 seconds (`CONTROL_CACHE_TTL` since step 8); a vehicle the directory does not hold has no eras. `Party` reads the `parties` table, set by `PUT /parties/:did` from a DID in `ADMIN_DIDS`; an org registered here with no row is `KindOrg` and not an operator, and any other unlisted DID is `KindUnknown`. `/authorize` is open to the DIDs in `ISSUER_DIDS`, refuses `at`, evaluates under `DefaultPolicy` at the host clock and returns the coverage plus `at`; refusals are 403 with a `code` naming the evaluator's error, and `exclusive_hold` carries the suspended abilities, for which `delegation.ExclusiveHoldError` now exists. A tombstone the org wrote itself has `by = ""` on the commit and is handed to the evaluator as the org DID, since `revokedAt` compares it to `from`.

### 3.4 Other reads

- `GET /orgs/:org/:collection[/:rkey]` for members with a read role or `org:admin`. As built (step 4): the org itself, or any member holding a live role, reads every collection but `vehicleControl`; the openings, and `GET /orgs/:org/commits` which carries them, take `org:admin`. Scoping a member's reads to their role's covers is not done.
- `GET /orgs/:org/delegations/:rkey/proof?vehicle=` returns the §11.3 bundle: chain records with their commits, memberships, the opening, and the era log. Anyone holding the delegation's `to` may fetch it.
- `GET /orgs/:org/delegations/:rkey/descendants` for the delegation's `from`, resolved per vehicle. This is the consent transparency view (§9.3).
- `GET /orgs/:org/pending` for approvers.

As built (step 6): **a proof is the transcript of one evaluation.** `GET .../proof?vehicle=` runs `Evaluator.Coverage` at the host clock through a recording resolver (`orghost.recorder`) that keeps every record, role, membership, custody period, opening and exclusive claim the evaluation read, plus the party attributes, tag sizes and era log it was given, and bundles them as `proof.Proof`: the commit behind each record and the tombstone commit of any that was revoked, each org's `#dimo_org` key, the control state, the asserted parties and counts, and the coverage concluded. `pkg/proof.Verify` checks every commit's signature, CID and canonical form against the key, then replays the same evaluator over a resolver backed by the bundle (`pkg/proof` implements `delegation.Resolver` over the commits) and refuses a proof whose records give a different coverage from the one claimed. The verifier is offline by construction: it holds no store and no client. `proof.Anchors` lets the verifier supply the keys and era log it fetched itself, and `proof.DirectoryAnchors` fetches them from a directory client; without anchors the bundle's own are used, which shows consistency with what the host said the directory held and nothing more. Parties and tag sizes are DIMO's and the host's say-so respectively and are carried as asserted, not verified. A proof does not show what the host left out: a tombstone the host omitted is not missed by a verifier holding a slice of the log, so the proof makes the host's answer checkable rather than unnecessary. The org's `to` and the org itself may fetch a proof; an evaluation that refuses answers as `/authorize` does, with the code, since there is no proof of what was not granted. `at` is the host clock, as for `/authorize`: the party who wants a record of their access fetches the proof while they have it.

**Descendants** are found by `Store.DelegationsWithBasis(uri)`, live delegations from every repository on the host whose `basis` names the URI (a GIN index over `record_json->'basis'` in Postgres), walked breadth first from the root to the chain depth limit. Each is resolved over the vehicle the owner asks about, which is required: a tag-based agreement downstream of a consent is only answerable per car. A descendant that no longer evaluates is listed with the refusal code rather than dropped, so a record the dealer wrote to somebody the allowlist does not name is visible as `not_narrowing`, and after the owner tombstones the consent every descendant shows `revoked` in one step. The view is for the delegation's `from` only.

### 3.5 Revocation

- `DELETE` a record: tombstone commit with `by = committedBy`. The evaluator ignores tombstones by a principal `revocableBy` does not allow, so the host refuses those at write time as UX.
- `POST /orgs/:org/revoke-authored-by {member, since}`: lists every record the member authored after `since`, returns it for review, and tombstones the reviewed set as one batch under one approval.

As built (step 4): **a member's tombstone is the org's act.** The evaluator honours a tombstone written by a principal `revocableBy` names, or by a member of one who held, at tombstone time, a role covering the record with the ability that manages records of its kind (`delegation.ManageAbility`: `delegation:create`, or `org:members` for a role). Revoking takes less than authoring: the abilities the record hands out are not needed to take it away. Before this the plan as written meant only the org DID itself could revoke anything. The host's `DELETE` runs the same rule (`checkTombstone`), so a lien is the lender's, or its staff's, to release. The recursion through roles and tombstones is bounded by chain depth and a role cannot vouch for its own author. `revoke-authored-by` with `uris` checks every tombstone as a `DELETE` by the caller would be, before any is written, and answers 400 for a URI outside the listed set; "authored" means the record's current version was committed by the member after `since`.

## 4. Data model

Postgres, one database, mirroring `internal/store` conventions:

```
orgs            (did pk, signing_key_enc, party jsonb, policy_name)
commits         (org, seq, prev, rev, op, collection, rkey, record jsonb,
                 committed_by, approved_by text[], committed_at, sig,
                 pk (org, seq), unique (org, collection, rkey, rev))
heads           (org, collection, rkey, seq, tombstoned_at, tombstoned_by)   -- current view
pending         (id, org, collection, rkey, record, committed_by, reasons, created_at)
```

Derived indexes for the resolver are plain btrees on `heads` joined to `commits`. No separate materialised coverage table in v1.

## 5. Changes elsewhere

**did-directory, before the host can exist:**
- The CLI can set `#dimo_org` and `#dimo_org_host` on an org DID. **Done 2026-09-22:** `dimocli create --org [--org-key did:key] [--org-host URL]` publishes the commit key (generated into the keystore as `<did>.org.json`, or supplied by the host) and the `DimoOrgHost` service entry; `update --org-key | --new-org-key | --org-host` sets them on an existing DID; `rotate` keeps `#dimo_org`; `pubkey --org` prints it. Controlled DIDs refuse all three.
- `pkg/client` gains only `ErrNotFound`, so the host can tell an unknown vehicle from a directory outage; it uses `Control` and `Resolve`.
- `pkg/agreement` gains a small client: compile, then `PUT` each grant and custody period to the host under the booking role, and tombstone the keys that dropped out. This is the booking SDK (decision F). It may move to its own repo later; nothing here depends on it.

As built (step 5): `pkg/agreement/booking` is that client, and `pkg/agreement` gains one pure function, `Keys`, to make it stateless. `booking.Client{Host, Token, HTTP}.Sync(ctx, agreement, catalog, now)` compiles, writes every custody leg of the agreement under `bookingID:<leg start>` (`booking.CustodyKey`) as a `network.dimo.org.custody` record with the assignee as holder, `PUT`s every compiled grant under its `Grant.Key`, and then tombstones every key that `agreement.Keys` lists and the compilation did not produce, if it is live. `Keys` is every key the agreement could ever compile to, in every state: one per line item and offer, one per incident, open or closed, for a per-incident offer. It is derived rather than listed because the host orders a listing by its database's collation, so a scan by key prefix is not an operation the host offers; the set is complete because nothing leaves an agreement. Custody is written first, grants before tombstones, and a refusal from the host comes back as `*booking.Error{Status, Method, Path, Message}` with the sync stopped there; calling again finishes it. A write the host parks answers in the result as `Op == booking.OpPending` with the pending id and reasons rather than as an error, which is how a booking role under the wrong policy shows itself. Every sync recommits the live grants, since `CreatedAt` is the compilation time; nothing is compared first.

**dauth:**
- `/exchange` takes `{grant: at-uri, vehicle, abilities}` plus DPoP, calls the host's `/authorize` with the authenticated `sub` as `caller`, and mints the §11.1 token with `grants[0] = {subject, abilities, windows}` and the chain from `Coverage.Chain`. Lifetime 15 minutes if any live ability, else 2 hours.
- Issues identity tokens the host accepts (decision B).

**dq:**
- `DQClaim` reads `grants`; the vehicle check passes when `subject` matches; resolvers clamp the requested range to `windows`. Fleet query stays out.

As built (step 7), in the dauth repo: **sign-in is by DID, not by Ethereum address.** Decision B needs `sub` to be a DID, and a spec §4 person holds a passkey, not a wallet, so the SIWE surface is replaced by `/signin`: `POST /signin/challenge {did}` returns a challenge text and a single-use nonce; `POST /signin/token {nonce, signature, key?}` verifies an ECDSA signature over the SHA-256 of the challenge (the directory's own r||s form, `pkg/didkey`, now public for this) against the verification method the DID document lists at token time (`#signing` by default; `#dimo_org` is refused as a login key), and mints an RS256 identity token with `sub` = DID. `dimocli signin` drives it from the keystore. The on-chain SACD exchange, the developer-licence check, the gRPC `AccessCheck` service, `pkg/grpc` and the swagger specs are deleted (spec §19 decision 17); `pkg/tokenclaims` is rewritten. `/exchange` is `POST /exchange` with an identity token and an RFC 9449 DPoP proof (`pkg/dpop`, ES256 or RS256, five-minute proofs, per-process replay cache); it calls the host's `/authorize` as `DAUTH_DID` with an identity token from its own sign-in issuer, and mints `{sub: caller, aud, cnf: {jkt}, grants}`. **A grant is one (subject, window set):** the host's per-ability windows are grouped, so abilities with the same windows share a grant, live abilities get a grant with no windows, suspended abilities are left out, and every grant carries the chain. **An app attests itself as a caller does:** `client_assertion` on the exchange is an identity token for the app's DID from the app's own sign-in; dauth verifies it like the caller's and sends its `sub` as `clientId`, which is what `clientAllowlist` names. Without one no client is claimed and an allowlisted delegation refuses. The host is faked in dauth's tests; the whole chain runs in step 8.

As built (step 7), in the dq repo: `DQClaim` embeds the new `tokenclaims.Token`, validated on the way in (`Token.Validate`); the audience is `TOKEN_AUDIENCE` (default `dq`). **Every authenticated HTTP request must carry a DPoP proof** for its method and URL with `ath` over the token, and the proof's thumbprint must equal `cnf.jkt`; the public URL for `htu` comes from `PUBLIC_BASE_URL` when dq is behind a proxy. The `Privilege` enum keeps its names and maps to abilities (`VEHICLE_NON_LOCATION_DATA` → `telemetry:read`, both location privileges → `location:precise`, `VEHICLE_APPROXIMATE_LOCATION` → `location:approximate`, `VEHICLE_RAW_DATA` → `raw:read`, `VEHICLE_VIN_CREDENTIAL` → `documents:read`, `VEHICLE_COMMANDS` → `command:unlock`), since the enum is what model-garage's signal definitions name. `@requiresVehicleToken` finds the grants for the query's `subject` and, on a field with `from`/`to`, **clamps the range to the union of the subject's windows**: nothing left refuses, and a range that straddles a gap is refused with the windows named, so the caller splits the query (spec §11.4 wants merged segments; v1 refuses rather than interpolates). The privilege directives then check each required ability for the subject and, when a ranged ancestor is in scope, that its windows contain the clamped range; a field with no range in scope (latest, snapshot, summary) needs the windows to contain now. Cloud-event reads take `raw:read` and have `after`/`before` injected from the windows the same way. The device-to-vehicle link through identity-api and `IDENTITY_API_URL` are gone: the requested subject must be a grant subject. The gRPC fetch port keeps bearer validation and takes `raw:read` over the requested subject; it does not check DPoP, with the NetworkPolicy as the compensating control.

As built (step 8): **the demo is the integration test, and it runs the real binaries.** `scripts/demo.sh` starts `cmd/did-directory`, `cmd/org-host` and dauth's `cmd/dauth` as child processes with in-memory stores and throwaway RSA keys, on `:8082`, `:8081` and `:8080`, wires them the way production would (the host trusts `…/signin/keys`, `ISSUER_DIDS` names `DAUTH_DID`, `ADMIN_DIDS` names a DIMO DID the script creates first) and stops them at the end. Every record the script writes is plain JSON built with `jq` and sent with `curl` under a `dimocli signin` token, so the wire format is what a real client sends. What the story exercises, in order: an org DID created with `--org --org-host`, registered on the host with the CLI-generated `#dimo_org` key and attested an operator by DIMO; three controlled vehicle DIDs whose openings the org commits to its repository; three tags; an admin role that commits directly, a fleet-manager role, and a booking role under the `rental-booking` policy that parks and is approved by the admin; memberships; the insurer grant by the fleet manager, the lender's lien and the telematics partner's command grant parked and approved (with the lender's own approval refused); the partner's own repository redelegating telemetry to an integrator, whose token carries a two-repository chain; the descendants view; a booking driven through `dimocli booking` from an agreement file (paid → assigned → pickup and breakdown synced → returned), with the renter's live token, the partner's `exclusive_hold`, roadside's incident window, the tombstones at return and the renter's drive window; a sale by `dimocli transfer`, after which the lien and the commands refuse `not_covered`, the insurer's and the renter's windows end at the transfer, and the buyer registers a repository with a host-generated key, publishes it as `#dimo_org`, commits the era-1 opening and consents to the insurer over one car; and finally the renter's coverage proof, fetched, then verified by `dimocli verify-proof` against the directory after the org host process has been killed.

Three things the building settled. **A history grant is nothing until custody syncs**: `narrowToCustody` with no custody period for the renter narrows the window to empty, so the renter's history token before the pickup event is `not_covered`, which is the spec's intent (§12.1: "custody only") and the demo shows it as such rather than working around it. **`dimocli exchange` binds the token to the caller's `#signing` key**: the DPoP proof is an ES256 JWS made with the keystore key, hand-assembled because dauth's `pkg/dpop` cannot be imported here without a module cycle; the signature encoding is the r||s form `internal/crypto.SignOperation` already produces, which is the JWS form. `--client` attests an app by signing in as its DID too. **The control cache is a setting**: `Resolver.ControlCacheTTL` and `CONTROL_CACHE_TTL` (default 30s) exist so a demo can show a transfer within a second of it; nothing else changed on the host.

**dq runs too, with din played by a seed tool.** dq boots single-node on a file-backed DuckLake catalog with no Postgres, S3 or NATS, and carries a `did:dimo:` subject through verbatim once no vehicle NFT contract is configured. What it lacked was data: `cmd/dq-seed` in the dq repo writes `dimo.status` events with a speed signal into `lake.raw_events` in din's shape and runs the materializer over them once, so dq boots with the decoded tables already present. Two facts shaped that: the file catalog has one writer, so the seed runs before dq starts; and a query connection that attaches the catalog before the decoded tables exist does not see them later, so decoding in the seed tool rather than in dq's own loop is what makes the first query work. `dimocli query` mints a token as `exchange` does and sends a GraphQL query with a DPoP proof for that request (`ath` over the token) from the same key. The demo's rental is backdated (custody events sync late, spec §12.3: the pickup was 30 minutes ago, the return 10) and an hour of readings is seeded, so the renter's clamp to the drive, the insurer's clamp to the Avis era and the buyer's consent since the sale each show as a different set of five-minute buckets of the same data. `signalsLatest` under a live consent is not shown: `lake.signals_latest` is maintained by dq's daily watermarked refresh, and today's rows are not in it on a fresh catalog; the renter's `signalsLatest` refusal is the directive's own answer and is shown.

## 6. Sequence

Each step ends with something runnable.

1. **CLI org keys.** `dimocli` can create an org DID with `#dimo_org` and set `#dimo_org_host`. Half a day. **Done 2026-09-22** (§5).
2. **Repository core.** Commits, signing, heads, tombstones, `ValidateRKey` on every write, in-memory and Postgres stores, `GET` for members. No checks yet beyond structure. Test: write, read back, verify the chain and every signature offline. **Done 2026-09-22:** `pkg/repo` (commit, canonical JSON, TIDs, `VerifyLog`), `internal/orghost` (sealed keys behind `repo.Signer`, JWKS identity tokens, structural checks, write path) and `internal/orghost/store` (memory and Postgres), served by `cmd/org-host`. Until step 4 any authenticated DID may read or write any repository; the commit records who did. See §3.1 for what the commit gained.
3. **Resolver and `/authorize`.** Implement `delegation.Resolver` over the store and directory. Test: the Avis fixtures from `pkg/agreement/evaluate_test.go` replayed through HTTP produce the same coverage. **Done 2026-09-22:** `internal/orghost.Resolver`, the store's resolver queries with partial expression indexes over the derived jsonb (memory and Postgres), the `parties` table and routes, `POST /authorize`, and `DIRECTORY_URL`, `ISSUER_DIDS`, `ADMIN_DIDS` settings. `TestCompiledGrantsAuthorizeOverHTTP` and `TestInsurerGrantAuthorizesOverHTTP` are the replay, driven at fixed host-clock times. See §3.3 for what was settled in the building.
4. **Write-time checks and approval.** Roles, `CheckCommit`, `CheckMembershipGrowth`, pending writes, second approval, `revokeAuthoredBy`. Test: the spec §13.1 table, action by action. **Done 2026-09-22:** `internal/orghost/access.go` (the per-collection role checks, `CheckCommit` under the role's named policy, §9.2 and growth checks on memberships, approver rules, tombstone and read checks), `pending.go` (pending list, approve, withdraw, `revoke-authored-by`), the `pending` table and the `Authored` and `DelegationsOverTag` queries in both stores. `pkg/delegation` gained `RolesCovering`, `HeldRoles`, `CoveredVehicles`, `ManageAbility`, `AuthoringNeed`, `MembershipNeed`, `Revokers`, `RoleConstraints.Policy`, the member-tombstone rule and the role-author check. `TestAvisActions` is the §13.1 table over HTTP against both stores. See §3.2, §3.4 and §3.5 for what was settled in the building.
5. **Booking SDK.** The `pkg/agreement` client from §5 against the running host. Test: booking → paid → picked up → returned driven from a test booking service, then `/authorize` for the renter and the blocked operator. The host's code does not change in this step. **Done 2026-09-22:** `pkg/agreement/booking` (`Client.Sync`, `CustodyKey`, `Error`, `OpPending`) and `agreement.Keys`. `TestBookingServiceDrivesTheHost` in `internal/orghost` is the test, against both stores: a booking service holding one agreement moves it booked → paid → assigned → picked up → breakdown → returned → retention over, syncing after each move through the SDK over a real `http.Client` into the host, with `/authorize` asked for the renter, the roadside responder and the valet crew at each stage, and the log verified offline at the end. Cancellation, refusals and the pending path have their own tests. The host did not change. See §5 for what was settled.
6. **Proofs and descendants.** Coverage proof bundle plus an offline verifier in `pkg/proof`; descendants listing. Test: a proof verifies with the host down. **Done 2026-09-22:** `pkg/proof` (`Proof`, `Verify`, `Evaluate`, `Anchors`, `DirectoryAnchors`), `internal/orghost/proof.go` (the recording resolver, `GET /orgs/:org/delegations/:rkey/proof` and `/descendants`) and `Store.DelegationsWithBasis` in both stores. `TestCoverageProofVerifiesWithTheHostDown` fetches the renter's history-grant proof, shuts the host down, and verifies it against the bundle and against the directory's key and era log; `TestDescendants` is the §13.2 owner-consent view through a dealer and a lender. See §3.4 for what was settled in the building.
7. **dauth exchange**, then **dq clamping**, in their repos, against a running host. **Done 2026-09-22** in the dauth and dq repos, with `pkg/didkey` and `dimocli signin` here; each repo's own tests fake its neighbour, and both take this repo and dauth through `replace` directives until they are tagged. See §5 for what was settled in the building.
8. **A new `scripts/demo.sh`** replacing the deleted one: org, fleet, three partners, one booking, one sale, tokens at each step. This is the first time the whole model runs. **Done 2026-09-22:** the script builds and starts the directory, the org host, dauth and dq (from sibling checkouts, `DAUTH_DIR` and `DQ_DIR`) in memory on one machine, then walks spec §13.1 and §13.3 end to end with every token minted by dauth's `/exchange`, and ends with three parties querying one car's telemetry through dq, each clamped to its own windows. `dimocli` gained `exchange`, `booking`, `query` and `verify-proof` for it; dq gained `cmd/dq-seed`. See §5 for what was settled in the building.

## 7. Open questions carried

- **Cross-org chains and self-hosting.** A chain from Ford Pro's repo through Avis's repo is one database in v1. When an org self-hosts, `Record` and `Opening` have to fetch from another host, and that host has to decide whether to answer. Coverage proofs are the likely currency. Not designed.
- **Membership author authority (§9.2)** is checked by the evaluator from `Membership.CreatedBy`. The host must populate that from `committedBy`, not from the request body, for the same reason as `Stored.CommittedBy`.
- **Custody and exclusives are host-wide.** `Resolver.Custody(vehicle, holder)` and `Exclusives(vehicle, at)` carry no org, so they read every repository on the host. A custody record in org B's repository therefore widens a custody-narrowed grant from org A, up to A's own data window, and an exclusive claim in B suspends A's live abilities. Step 4's role checks bound who may write either; scoping them to the issuer's repository instead would need the `Resolver` to be told which grant is asking, or the record's controller to be found through the directory on every call. Left host-wide for now.
- **Device-synced custody.** A custody period signed by the car's device arrives late and out of order. Whose write is it, under what role? Provisionally the operator's booking service, with the device signature kept on the record for audit.
- **`revokeSince` ending the era** was motivated by bearer SACDs, which no longer exist (spec §19). Leave as is until someone needs the simpler behaviour.
- **What an app / `clientId` is.** A DID with a key, attested to dauth by the app's own sign-in (`client_assertion`, step 7). Still open: who may create an app's DID, and whether a `clientAllowlist` should name DIDs directly or something an org registers.
