# Replacing the identity-api — October 1, 2026

## The question

The old identity-api showed every object in DIMO and how they related: vehicles, owners, devices, manufacturers, SACD permissions. Apps queried it, and it needed no authentication because everything it showed came from the chain, where anyone could already read it. One indexer read everything and served everything.

Under the delegation design, that is no longer true. Spec design goal 7 makes it a requirement: **fleet composition is private**. Nothing public may tell an observer which cars an org controls. An index of the whole graph, open to everyone, is exactly what the design forbids. This note proposes what replaces it.

## What is readable today

| Where | What | Who can read it |
|---|---|---|
| **did-directory**: `/export`, `/:did`, `/:did/data`, `/:did/control`, `/:did/log/audit` | DIDs, verification methods, service entries (`#dimo_org_host`, `dimo_storage`), `alsoKnownAs`, op history, era and era start, and the control **commitment**, but not the controller | Anyone |
| **org host**: `/orgs/:org/:collection[/:rkey]` | Delegations, roles, tags, memberships, custody | The org itself, or any DID holding a live role in it |
| **org host**: `vehicleControl` openings, `/orgs/:org/commits` | Which vehicles the org controls; the full log | The org, or a member with `org:admin` |
| **org host**: `/orgs/:org/delegations/:rkey/proof` | A coverage proof for one delegation over one vehicle, with the commitment opening for that vehicle only | The delegation's recipient, or the org |
| **org host**: `/orgs/:org/delegations/:rkey/descendants` | Every live delegation below one root, resolved over a vehicle (spec §9.3) | The org that issued the root |

Every org host route takes a dauth identity token (`sub` = DID, `aud` = the host), checked by `JWKSAuthenticator` against `IDENTITY_AUDIENCE`.

## Proposal

The replacement is not one new service. The public part is the directory, which already exists; the private part is the org host, read by each caller with their own token. The org host needs a few routes added.

### Public: the directory as it is

The directory already answers what the public part of the identity-api answered about a DID: its keys, its services, its era. It cannot say who controls a vehicle, and must not: the commitment is there to stop exactly that.

The op history has to stay public, because verifiers need it. `pkg/proof.Verify` and `dimocli verify-proof` check a coverage proof against the directory's `#dimo_org` keys and era log, and a resolver needs the whole log to trust a DID's current state. We should not, however, build a searchable index over that history. `/export` already lets anyone download every op in order, so an index adds no new information, but it makes linking cars much cheaper: a batch of vehicle DIDs created in the same minute is probably one org's fleet. Spec §10 defends against that by staggering publication of batch onboarding, and an index of creation times would make whatever pattern remains easy to see. Nothing in this design needs such an index.

Nor should the directory look DIDs up by `alsoKnownAs`. The field is whatever the DID's controller wrote: nothing verifies it, and two DIDs can claim the same name. A lookup would present it as an answer it cannot be.

### Private: built from what the caller can already read

The private graph is not indexed centrally. A caller signs in with their DID through dauth, gets an identity token whose audience is the org host, and asks the org host directly. What they see is exactly what that token can already read:

- **As an org admin:** the fleet (`vehicleControl` openings), tags and memberships over time, every outbound delegation and role, pending approvals, the commit log.
- **As a member with a narrower role:** what the role's read scope admits (see gap 2 below).
- **As a grantee:** their inbound delegations, and for each covered vehicle a coverage proof that opens its commitment. A grantee learns about the cars it covers and nothing else.
- **As an issuer, including a person who owns one car:** everything below each grant they gave, resolved per vehicle. That answers "who can see my car". It holds at every level: if Ford Pro redelegates its grant to an integrator, Ford Pro issued the integrator's grant, so it sees that grant and everything below it. Its child grants are records in its own repository, and `/descendants` on each of them reaches the rest.

No new trust is involved: callers use APIs that already enforce access. If apps want the old GraphQL query shape, a facade can provide it later, as long as it forwards the caller's own token and holds no credential of its own.

## Why not a central index with access rules

The old service's shape, with access rules added, would mean an indexer that reads every org's repository and filters what it returns by the caller's roles. We should not build that:

- **It concentrates the private data.** Every org's fleet and partner list in one database is the single target that the commitment scheme and per-org repositories exist to avoid.
- **It copies the authorization logic.** The filter would have to agree with the org host's `checkRead`, the evaluator and the proof rules at every point. Both reviews found the same bug: authority read from state the reader had not established (the 2026-09-17 review and the [2026-09-23 compliance review](2026-09-23-spec-compliance-review.md)). A second implementation of the same rules, working from a copy that lags the log, invites it again.
- **It fails open.** A filter that misses a case shows private records. A client that asks the host fails closed: the host refuses.

## What the org host needs first

### Gap 1: "what do I hold?"

Every org host route starts from `:org`. A member has no way to discover which orgs gave them a role, because members are not listed in DID documents (spec §6.3). A grantee likewise cannot discover which delegations name them. No app can begin without that.

Add two routes, scoped to the caller:

| Route | Returns |
|---|---|
| `GET /me/roles` | Live roles addressed to the caller, from every repository on the host, with each role's org |
| `GET /me/delegations` | Live delegations whose `assignee` is the caller, from every repository on the host |

**Built:** both routes are in `internal/orghost/me.go`, over a new `Store.Assigned(collection, assignee)`: the records in one collection, from every repository on the host, addressed to the caller, tombstones included, since the evaluator decides whether a tombstone counts. Postgres has `commits_assignee_idx` for it; the existing `commits_role_assignee_idx` leads with `org` and could not serve a host-wide lookup. `/me/roles` lists only the roles `HeldRoles` finds live, in orgs that can have members, which is what `checkRead` admits. `/me/delegations` cannot do the same, because a delegation gives something only over a vehicle. Without `?vehicle=` it lists the records as stored; with it, each is resolved over that vehicle, with coverage or a refusal code, as `/descendants` does. This tells the grantee nothing `/proof` does not already: the recipient may ask that for any vehicle. Neither route pages yet. With one DIMO-hosted org host in v1, this answers the question completely. Once orgs self-host, a grantee's delegations can sit on hosts it has never heard of, which needs an inbox or for grantees to register the hosts they use. That can wait until self-hosting is real.

### Gap 2: scoped reads

Spec §6.2 says the repository is "readable only by org members holding `org:admin` or a scoped read role". The org host is looser than that. `checkRead` (`internal/orghost/access.go:473`) lets any role holder read delegations, tags and memberships; only `vehicleControl` and the log need `org:admin`. Its comment records the gap ("Scoping a member's reads to their role's covers is not done in v1"). So a booking service's role, which exists only to write rental grants, can list every partner agreement and every tag membership.

This is a deviation from the spec, not a missing feature, and it exists today whether or not an app is built. An app that lets members browse the repository only makes it visible: the first member who opens it sees everything. Reads should take an ability: `org:read`, say, with `scope` limiting which tags and collections. Roles without it would read nothing but their own records.

### Gap 3: one view per vehicle, and per received grant

`/descendants` starts from one root. Two common questions need several calls today:

- **"Who can reach this car?"** for the controller. They would have to find every root first: delegations naming the vehicle, delegations over every tag it was ever a member of, and exclusive holds. Add `GET /orgs/:org/vehicles/:vehicle/access` for the org or `org:admin`, which does that walk and returns each path with its evaluation, as `/descendants` does. `Exclusives` and `DelegationsOverTag` already provide most of the lookups.
- **"What did we pass on from this grant?"** for a recipient that redelegated it. `/descendants` answers only the org whose repository holds the root, and the grant Ford Pro received sits in RentalCo's repository, so Ford Pro is refused. It has to list its own delegations, pick those whose basis is the grant, and call `/descendants` on each. Letting the recipient (`caller == record.to`) call `/descendants` on the grant it received returns the same set in one call. That shows it nothing new: a child that evaluates must be issued by its parent's recipient (`evaluate.go`, `child.From != parent.To`), so every working descendant is Ford Pro's own or below one of its grants. The listing also includes records that do not evaluate, with their refusal codes. Anyone can write one naming any basis, and the root's issuer already sees those.

## What happens to the rest of the identity-api

| Old object | Replacement |
|---|---|
| Vehicles, owners, devices | DIDs in the directory; control and permissions in org repositories, as above |
| SACD permissions | Delegations (`network.dimo.delegation`) |
| Manufacturers, device definitions | Verifiable credentials; a separate design |
| DCNs | `alsoKnownAs`, provisionally: a DID's own claim, unverified and not unique |
| Rewards | Dropped |

## Order of work

1. **`/me/roles` and `/me/delegations`.** Built (see gap 1). Without them no app could start.
2. **Scoped reads.** This brings the host back in line with spec §6.2, so it is due regardless. It must land before any app lets members browse a repository.
3. **The per-vehicle access view, and `/descendants` for recipients.** These are the views owners and partners will care about most.

A browsing UI over all of this is optional, and not part of the replacement.
