#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# DIMO orgs, fleets and delegation — end-to-end demo
#
# Org host plan §6 step 8: the first time the whole model runs. Four services
# on this machine, all in memory:
#
#   DID directory  (:8082)  who controls which vehicle, as commitments and eras
#   org host       (:8081)  every org's private records: signed commit logs of
#                           roles, tags, memberships, delegations, custody
#   dauth          (:8080)  sign-in by DID, then /exchange: asks the host to
#                           authorize and mints a DPoP-bound access token
#   dq             (:3000)  the data service: serves telemetry from a DuckLake
#                           catalog, clamped to the windows the token carries
#
# The story is spec §13.1. Avis registers as an org, onboards three cars it
# controls, tags them, and grants three partners: an insurer, a lender and a
# telematics partner that passes telemetry on to an integrator. A renter books
# a car: the booking service compiles the agreement into grants, the renter
# unlocks the car, the telematics partner is locked out while somebody is
# driving, roadside gets a location for the length of a breakdown, and at
# return the renter keeps the history of the days they drove. Then Avis sells
# the car: a new era starts, the lender and the partner lose the car, the
# insurer and the renter keep their history, and the buyer starts clean. At
# every step a party asks dauth for a token and we show what it carries, and
# at the end the same car's telemetry is queried under three grants — the
# renter's, the insurer's from Avis and the insurer's from the buyer — and
# each gets the slice its delegation allows.
#
# Nothing here touches a chain. Every authorization is a signed record in an
# org's repository, evaluated by the host, checkable offline.
#
# DEMO_PRESENT=1 runs it for a room: one step per screen, a keypress between
# steps and before the key moments, tokens as one line per grant. DIDs are
# shown by name throughout (car-1, Avis, Renter); the closing summary has the
# real identifiers. DEMO_VERBOSE=1 logs every CLI request.
#
# Every delegation and role the host stores is an ODRL policy. In presenter
# mode, a step that wrote any offers to show them before moving on: press o.
# DEMO_ODRL=1 prints them after every step, presenter mode or not.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DAUTH_DIR="${DAUTH_DIR:-$PROJECT_DIR/../dauth}"
DQ_DIR="${DQ_DIR:-$PROJECT_DIR/../dq}"

DIRECTORY_PORT="${DIRECTORY_PORT:-8082}"
ORG_HOST_PORT="${ORG_HOST_PORT:-8081}"
DAUTH_PORT="${DAUTH_PORT:-8080}"
DQ_PORT="${DQ_PORT:-3000}"
DIRECTORY_URL="http://localhost:$DIRECTORY_PORT"
ORG_HOST_URL="http://localhost:$ORG_HOST_PORT"
DAUTH_URL="http://localhost:$DAUTH_PORT"
DQ_URL="http://localhost:$DQ_PORT"
DAUTH_DID="did:dimo:dauth"

DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dimo-demo-XXXXXX")"
BIN="$PROJECT_DIR/bin"
DIMOCLI="$BIN/dimocli"
KEYS="$HOME/.dimo/keys"
PIDS=()
PRESENT="${DEMO_PRESENT:-0}"
ODRL="${DEMO_ODRL:-0}"
# The delegations and roles written since the last chance to look at them.
WRITTEN="$DEMO_DIR/written"
: >"$WRITTEN"
[ "${DEMO_VERBOSE:-0}" = "1" ] && export DIMO_VERBOSE=1

# Every DID the story creates gets a name here; output helpers replace the
# DID with it. bash 3.2 has no associative arrays, so this is a sed script.
NAMES_SED="$DEMO_DIR/names.sed"
: >"$NAMES_SED"
name() { printf 's|%s|%s|g\n' "$1" "$2" >>"$NAMES_SED"; }
named() { sed -f "$NAMES_SED"; }

# ── Output helpers ────────────────────────────────────────────────────────

# pause waits for a keypress in presenter mode and does nothing otherwise. If
# policies were written since the last one, the keypress can be o to see them.
pause() {
    peek && return 0
    [ "$PRESENT" = 1 ] || return 0
    echo ""
    echo -en "  ${DIM}— press any key —${NC}"
    { read -r -s -n1 </dev/tty; } 2>/dev/null || true
    echo -en "\r\033[K"
}

FIRST_HEADER=1
header() {
    if [ "$PRESENT" = 1 ]; then
        [ "$FIRST_HEADER" = 1 ] || pause
        clear
    else
        peek || true
    fi
    FIRST_HEADER=0
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}
step()    { peek || true; echo -e "  ${YELLOW}>>>  $1${NC}" | named; }
success() { echo -e "  ${GREEN}[OK]  $1${NC}" | named; }
fail()    { echo -e "  ${RED}[FAIL]  $1${NC}" | named; }
info()    { echo -e "  ${CYAN}$1${NC}" | named; }
show()    { named | sed 's/^/        /'; }
json()    { jq . | show; }
# policy prints a stored record's ODRL policy. On a terminal it is highlighted,
# with the DIMO profile's terms in magenta so they stand apart from ODRL's own.
ESC=$(printf '\033')
policy() {
    if [ -t 1 ]; then
        jq -C .record | sed -E "s/${ESC}\[(1;34|0;32)m\"dimo:/${ESC}[1;35m\"dimo:/g" | show
    else
        jq .record | show
    fi
}
# created NAME DID announces a new DID with its real identifier and names it.
created() {
    name "$2" "$1"
    echo -e "  ${GREEN}[OK]  ${BOLD}$1${NC}${GREEN} is $2${NC}"
}

die() {
    fail "$1"
    exit 1
}

# CLI_ERR holds a dimocli command's stderr, kept apart from the JSON it prints
# on stdout. verbose_log shows it when DEMO_VERBOSE asked for request logs.
CLI_ERR="$DEMO_DIR/cli.err"
verbose_log() {
    [ "${DIMO_VERBOSE:-0}" = "1" ] && [ -s "$CLI_ERR" ] && show < "$CLI_ERR"
    return 0
}

on_exit() {
    local code=$?
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    # Let them exit before the directory goes: dq is still writing its catalog.
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && wait "$pid" 2>/dev/null || true
    done
    if [ "$code" -ne 0 ]; then
        echo ""
        fail "Demo failed (exit $code). Service logs are under $DEMO_DIR:"
        for log in "$DEMO_DIR"/*.log; do
            [ -f "$log" ] || continue
            echo -e "${DIM}--- $(basename "$log") (last 15 lines) ---${NC}"
            tail -n 15 "$log"
        done
    else
        rm -rf "$DEMO_DIR"
    fi
}
trap on_exit EXIT

# ── Time helpers (macOS and GNU date) ─────────────────────────────────────

iso() { # epoch seconds -> RFC 3339 UTC
    date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ
}
NOW_EPOCH=$(date +%s)
NOW=$(iso "$NOW_EPOCH")
# Roles, grants and memberships are valid from an hour before the run, so the
# telemetry seeded for that hour falls inside them. The rental happened in the
# last 40 minutes: the car's device syncs custody events late (spec §12.3), so
# a pickup 30 minutes ago and a return 10 minutes ago are what it reports now.
VALID_FROM=$(iso $((NOW_EPOCH - 3600)))
BOOKED_FROM=$(iso $((NOW_EPOCH - 2400)))
PICKUP=$(iso $((NOW_EPOCH - 1800)))
INCIDENT_OPENED=$(iso $((NOW_EPOCH - 1500)))
INCIDENT_CLOSED=$(iso $((NOW_EPOCH - 720)))
RETURN=$(iso $((NOW_EPOCH - 600)))

# ── Service and CLI helpers ───────────────────────────────────────────────

wait_for() { # url description
    for i in $(seq 1 40); do
        if curl -sf "$1" >/dev/null 2>&1; then
            success "$2 is up"
            return
        fi
        sleep 0.5
    done
    die "$2 did not come up at $1"
}

extract_did() { grep "DID created:" | awk '{print $3}'; }

# create NAME <dimocli create flags...> — creates a DID and prints it.
create() {
    local out
    out=$("$DIMOCLI" create -server "$DIRECTORY_URL" "$@" 2>&1) || { echo "$out" >&2; return 1; }
    local did
    did=$(echo "$out" | extract_did)
    [ -n "$did" ] || { echo "$out" >&2; return 1; }
    echo "$did"
}

# signin DID — an identity token addressed to the org host, which refuses a
# token addressed anywhere else.
signin() { "$DIMOCLI" signin --dauth "$DAUTH_URL" --did "$1" --audience "$ORG_HOST_URL"; }

# host METHOD PATH TOKEN [JSON] — calls the org host; sets STATUS and BODY.
host() {
    local method=$1 path=$2 token=$3 data=${4:-}
    local args=(-s -o "$DEMO_DIR/body" -w '%{http_code}' -X "$method"
        -H "Authorization: Bearer $token" -H 'Content-Type: application/json')
    [ -n "$data" ] && args+=(--data-binary "$data")
    STATUS=$(curl "${args[@]}" "$ORG_HOST_URL$path")
    BODY=$(cat "$DEMO_DIR/body")
    case "$method $path $STATUS" in
    PUT*/network.dimo.delegation*\ 20[012] | POST*/network.dimo.delegation*\ 20[012] | \
        PUT*/network.dimo.org.role*\ 20[012] | POST*/network.dimo.org.role*\ 20[012])
        echo "$BODY" | jq -r '.uri // empty' >>"$WRITTEN" ;;
    esac
}

# booking runs the booking service's sync and remembers the grants it wrote.
booking() {
    local out
    out=$("$DIMOCLI" booking --dauth "$DAUTH_URL" --server "$DIRECTORY_URL" --did "$BACKEND" --agreement "$AGREEMENT")
    echo "$out" | show
    echo "$out" | grep -o 'at://[^ ]*/network\.dimo\.delegation/[^ ]*' >>"$WRITTEN" || true
}

# peek offers the ODRL policies written since it last ran: in presenter mode
# on a keypress, with DEMO_ODRL=1 always. It returns 0 when it waited for a
# key, so pause need not wait again.
peek() {
    [ -s "$WRITTEN" ] || return 1
    local show_them=$ODRL waited=1 key=
    [ "$PRESENT" = 1 ] && waited=0
    if [ "$PRESENT" = 1 ] && [ "$ODRL" != 1 ]; then
        echo ""
        echo -en "  ${DIM}— o: see the ODRL just stored · any other key: go on —${NC}"
        { read -r -s -n1 key </dev/tty; } 2>/dev/null || true
        echo -en "\r\033[K"
        case $key in o | O) show_them=1 ;; esac
    fi
    if [ "$show_them" = 1 ]; then
        local status=$STATUS body=$BODY uri org rest token
        [ -t 1 ] && echo -e "  ${DIM}ODRL's own terms in blue, the DIMO profile's in ${NC}\033[1;35mmagenta${NC}"
        for uri in $(sort -u "$WRITTEN"); do
            rest=${uri#at://}
            org=${rest%%/*}
            token=$(signin "$org")
            host GET "/orgs/$rest" "$token"
            echo ""
            case $STATUS in
            200) echo -e "  ${BOLD}$uri${NC}" | named ;;
            410) echo -e "  ${BOLD}$uri${NC} ${DIM}(tombstoned; this is what it granted)${NC}" | named ;;
            *) echo -e "  ${BOLD}$uri${NC} ${DIM}(not committed: HTTP $STATUS)${NC}" | named; continue ;;
            esac
            echo "$BODY" | policy
        done
        STATUS=$status BODY=$body
        if [ "$PRESENT" = 1 ]; then
            echo ""
            echo -en "  ${DIM}— press any key —${NC}"
            { read -r -s -n1 </dev/tty; } 2>/dev/null || true
            echo -en "\r\033[K"
        fi
    fi
    : >"$WRITTEN"
    return $waited
}

expect() { # status description
    if [ "$STATUS" = "$1" ]; then
        success "$2"
    else
        die "$2: HTTP $STATUS $BODY"
    fi
}

approve() { # org pending-id approver-token description
    host POST "/orgs/$1/pending/$2/approve" "$3"
    expect 201 "$4"
}

# Record builders. Delegations and roles are ODRL policies with the DIMO
# profile (spec §5): a grant is an Agreement, a role is a Set. The host parses
# each one, checks it structurally and against the writer's role (plan §3.2),
# and commits it with its uid set to where it lives. Tags, memberships and
# custody are facts, not permissions, and stay plain JSON.
#
# The jq below is the whole mapping a client needs: from/to are assigner and
# assignee, covers is the permission's target (a tag is an AssetCollection),
# abilities are dimo: actions, validity and purpose are ODRL constraints, and
# everything ODRL has no word for is a dimo: profile term.
ODRL_POLICY='
    def target: if .tag then {target: .tag, "@type": "AssetCollection"}
        elif .vehicle then {target: .vehicle, "@type": "Asset"}
        else {target: "dimo:inherit"} end;
    def actions: split(",") | map("dimo:" + sub(":"; "."));
    {"@context": ["http://www.w3.org/ns/odrl.jsonld", "https://schema.dimo.zone/odrl/v1"],
     "@type": $type, profile: "https://schema.dimo.zone/odrl/v1",
     assigner: $from, assignee: $to,
     permission: [($covers | target) + {action: ($abilities | actions),
         constraint: ([{leftOperand: "dateTime", operator: "gteq", rightOperand: $from_when}]
             + $constraints)}],
     "dcterms:issued": $now}'
role() { # org to covers-json abilities-csv [issue-constraints-json]
    jq -cn --arg type Set --arg from "$1" --arg to "$2" --argjson covers "$3" --arg abilities "$4" \
        --argjson issue "${5:-null}" --argjson constraints '[]' --arg now "$NOW" --arg from_when "$VALID_FROM" \
        "$ODRL_POLICY"' + (if $issue then {"dimo:issueConstraints": $issue} else {} end)'
}
grant() { # from to covers-json abilities-csv purpose [profile-terms-json] [client]
    local terms=${6:-} client=${7:-} constraints
    [ -n "$terms" ] || terms='{}'
    # Built into variables first: bash 3.2 mangles JSON inside "$(...)" arguments.
    constraints=$(jq -cn --arg purpose "$5" --arg client "$client" '
        [{leftOperand: "purpose", operator: "eq", rightOperand: $purpose}]
        + (if $client != "" then [{leftOperand: "dimo:client", operator: "isAnyOf", rightOperand: [$client]}] else [] end)')
    jq -cn --arg type Agreement --arg from "$1" --arg to "$2" --argjson covers "$3" --arg abilities "$4" \
        --argjson terms "$terms" --argjson constraints "$constraints" --arg now "$NOW" --arg from_when "$VALID_FROM" \
        "$ODRL_POLICY"' + $terms'
}
membership() { # tag-uri vehicle
    jq -cn --arg tag "$1" --arg vehicle "$2" --arg from_when "$VALID_FROM" '{tag: $tag, vehicle: $vehicle, joinedAt: $from_when}'
}

# mint DESCRIPTION CALLER GRANT-URI VEHICLE ABILITIES [CLIENT] — asks dauth for
# a token and shows what it carries.
mint() {
    local desc=$1 caller=$2 uri=$3 vehicle=$4 abilities=$5 client=${6:-}
    local args=(--dauth "$DAUTH_URL" --did "$caller" --grant "$uri" --vehicle "$vehicle" --abilities "$abilities" --claims)
    [ -n "$client" ] && args+=(--client "$client")
    step "$desc"
    local claims
    claims=$("$DIMOCLI" exchange "${args[@]}" 2>"$CLI_ERR") || die "expected a token: $(cat "$CLI_ERR")"
    verbose_log
    if [ "$PRESENT" = 1 ]; then
        success "$(echo "$claims" | jq -r '"token for \(.sub), \((.exp - .iat) / 60 | floor) min"')"
        echo "$claims" | jq -r '
            def t: if . == null then "open" else .[11:19] end;
            .grants[] | "\(.abilities | join(", "))   " +
              (if .windows then (.windows | map((.[0] | t) + " → " + (.[1] | t)) | join(", ")) + " UTC" else "live, no window" end) +
              "   via " + (.chain | join(" ← "))' | show
    else
        success "token minted"
        echo "$claims" | jq '{sub, lifetime: "\(.exp - .iat)s", grants: [.grants[] | {abilities, windows, chain}]}' | show
    fi
}

# refuse CODE DESCRIPTION CALLER GRANT-URI VEHICLE ABILITIES — expects dauth to
# refuse with CODE, the code the host answered with, and shows it. Any other
# failure (a service down, a sign-in refused) stops the demo rather than
# passing for the refusal.
refuse() {
    local want=$1 desc=$2 caller=$3 uri=$4 vehicle=$5 abilities=$6
    step "$desc"
    if "$DIMOCLI" exchange --dauth "$DAUTH_URL" --did "$caller" --grant "$uri" --vehicle "$vehicle" --abilities "$abilities" >/dev/null 2>"$CLI_ERR"; then
        die "expected a refusal ($want), got a token"
    fi
    local body code
    body=$(grep -o '{.*}' "$CLI_ERR" | tail -1 || true)
    code=$(echo "$body" | jq -r '.error // empty' 2>/dev/null || true)
    [ "$code" = "$want" ] || die "expected a refusal with $want, got: $(cat "$CLI_ERR")"
    success "refused: $(echo "$body" | jq -r '[.error, .error_description] | map(select(. != null and . != "")) | join(" — ")')"
}

SIGNALS_QUERY='query($subject:String!,$from:Time!,$to:Time!){ signals(subject:$subject, interval:"5m", from:$from, to:$to){ timestamp speed(agg:MAX) } }'
LATEST_QUERY='query($subject:String!){ signalsLatest(subject:$subject){ lastSeen speed{ timestamp value } } }'

# query DESCRIPTION CALLER GRANT-URI VEHICLE ABILITIES QUERY [VARIABLES-JSON] —
# mints a token and runs a GraphQL query against dq; shows what came back.
query() {
    local desc=$1 caller=$2 uri=$3 vehicle=$4 abilities=$5 q=$6 vars=${7:-}
    local args=(--dauth "$DAUTH_URL" --dq "$DQ_URL" --did "$caller" --grant "$uri" --vehicle "$vehicle" --abilities "$abilities" --query "$q")
    [ -n "$vars" ] && args+=(--variables "$vars")
    step "$desc"
    local out
    out=$("$DIMOCLI" query "${args[@]}" 2>"$CLI_ERR") || die "expected data: $(cat "$CLI_ERR")"
    verbose_log
    success "dq answered"
    echo "$out" | jq 'if .signals then {buckets: (.signals | length), first: .signals[0].timestamp, last: .signals[-1].timestamp, speed: [.signals[].speed]} else . end' | show
}

# query_refused REASON DESCRIPTION CALLER GRANT-URI VEHICLE ABILITIES QUERY
# [VARIABLES-JSON] — expects dq itself to refuse the query with a message
# containing REASON, and shows it.
query_refused() {
    local want=$1 desc=$2 caller=$3 uri=$4 vehicle=$5 abilities=$6 q=$7 vars=${8:-}
    local args=(--dauth "$DAUTH_URL" --dq "$DQ_URL" --did "$caller" --grant "$uri" --vehicle "$vehicle" --abilities "$abilities" --query "$q")
    [ -n "$vars" ] && args+=(--variables "$vars")
    step "$desc"
    local out reason
    if out=$("$DIMOCLI" query "${args[@]}" 2>"$CLI_ERR"); then
        die "expected dq to refuse, got: $out"
    fi
    reason=$(grep -o 'dq: .*' "$CLI_ERR" | head -1 | sed 's/^dq: //' || true)
    case "$reason" in
        *"$want"*) ;;
        *) die "expected dq to refuse with \"$want\", got: $(cat "$CLI_ERR")" ;;
    esac
    success "refused: $reason"
}

# ── Step 0: Prerequisites ────────────────────────────────────────────────

header "Step 0: Prerequisites and services"

for tool in go jq curl openssl; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done
[ -d "$DAUTH_DIR/cmd/dauth" ] || die "dauth checkout not found at $DAUTH_DIR (set DAUTH_DIR)"
[ -d "$DQ_DIR/cmd/dq" ] || die "dq checkout not found at $DQ_DIR (set DQ_DIR)"
for port in "$DIRECTORY_PORT" "$ORG_HOST_PORT" "$DAUTH_PORT" "$DQ_PORT"; do
    if curl -s --max-time 2 "http://localhost:$port/" >/dev/null 2>&1; then
        die "port $port is in use; stop what is listening there or set DIRECTORY_PORT, ORG_HOST_PORT, DAUTH_PORT and DQ_PORT"
    fi
done

step "Building did-directory, org-host and dimocli..."
mkdir -p "$BIN"
(cd "$PROJECT_DIR" && go build -o "$BIN/did-directory" ./cmd/did-directory && go build -o "$BIN/org-host" ./cmd/org-host && go build -o "$DIMOCLI" ./cmd/dimocli)
success "built into $BIN"
step "Building dauth from $DAUTH_DIR..."
(cd "$DAUTH_DIR" && go build -o "$BIN/dauth" ./cmd/dauth)
success "built $BIN/dauth"
step "Building dq and dq-seed from $DQ_DIR (CGO, embedded DuckDB)..."
(cd "$DQ_DIR" && CGO_ENABLED=1 go build -o "$BIN/dq" ./cmd/dq && CGO_ENABLED=1 go build -o "$BIN/dq-seed" ./cmd/dq-seed)
success "built $BIN/dq and $BIN/dq-seed"

step "Starting the DID directory (in memory) on :$DIRECTORY_PORT..."
DATABASE_URL="" PORT="$DIRECTORY_PORT" MONITORING_PORT=18888 LOG_LEVEL=warn \
    "$BIN/did-directory" -settings /dev/null >"$DEMO_DIR/directory.log" 2>&1 &
PIDS+=($!)
wait_for "$DIRECTORY_URL/health" "directory"

step "Starting dauth on :$DAUTH_PORT (throwaway RSA keys, in-memory challenge store)..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEMO_DIR/signin.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEMO_DIR/exchange.pem" 2>/dev/null
DATABASE_URL="" ENVIRONMENT=local LOG_LEVEL=info \
    HTTP_ADDRESS="127.0.0.1:$DAUTH_PORT" OPS_ADDRESS="127.0.0.1:18089" \
    PUBLIC_BASE_URL="$DAUTH_URL" DIRECTORY_URL="$DIRECTORY_URL" \
    SIGNIN_ISSUER="$DAUTH_URL/signin" JWT_AUDIENCE=dimo \
    SIGNIN_SIGNING_KEY_1="$(cat "$DEMO_DIR/signin.pem")" \
    EXCHANGE_ISSUER="$DAUTH_URL/exchange" EXCHANGE_AUDIENCE=dq \
    EXCHANGE_SIGNING_KEY_1="$(cat "$DEMO_DIR/exchange.pem")" \
    ORG_HOST_URL="$ORG_HOST_URL" DAUTH_DID="$DAUTH_DID" \
    "$BIN/dauth" >"$DEMO_DIR/dauth.log" 2>&1 &
PIDS+=($!)
wait_for "$DAUTH_URL/signin/keys" "dauth"

step "Creating DIMO's own DID: the party that attests who is an operator..."
DIMO=$(create --alias "dimo.zone")
created "DIMO" "$DIMO"

step "Starting the org host (in memory) on :$ORG_HOST_PORT..."
info "It trusts identity tokens from dauth's sign-in keys, lets $DAUTH_DID call"
info "/authorize, and lets DIMO set party attributes."
DATABASE_URL="" PORT="$ORG_HOST_PORT" LOG_LEVEL=info DIRECTORY_URL="$DIRECTORY_URL" \
    IDENTITY_JWKS_URL="$DAUTH_URL/signin/keys" IDENTITY_ISSUER="$DAUTH_URL/signin" IDENTITY_AUDIENCE="$ORG_HOST_URL" \
    ISSUER_DIDS="$DAUTH_DID" ADMIN_DIDS="$DIMO" CONTROL_CACHE_TTL=1s \
    "$BIN/org-host" -settings /dev/null >"$DEMO_DIR/org-host.log" 2>&1 &
PIDS+=($!)
wait_for "$ORG_HOST_URL/health" "org host"
DIMO_TOKEN=$(signin "$DIMO")

# ── Step 1: The org ───────────────────────────────────────────────────────

header "Step 1: Avis becomes an org"
info "An org DID carries two keys: #signing, which its service uses to sign in,"
info "and #dimo_org, the key the org host signs every commit of its repository"
info "with. The document also names the host (#dimo_org_host)."

AVIS=$(create --org --org-host "$ORG_HOST_URL" --alias "avis.com")
created "Avis" "$AVIS"
"$DIMOCLI" resolve -server "$DIRECTORY_URL" "$AVIS" | jq '{verificationMethod, service}' | show

step "Avis signs in to dauth with its #signing key and registers its repository..."
info "The CLI generated the #dimo_org key; the host takes the private half and"
info "seals it at rest. From here on only the host signs commits."
AVIS_TOKEN=$(signin "$AVIS")
AVIS_ORG_KEY=$(jq -r .privateKeyBase64 "$KEYS/${AVIS#did:dimo:}.org.json")
host POST "/orgs/$AVIS" "$AVIS_TOKEN" "$(jq -cn --arg k "$AVIS_ORG_KEY" '{privateKey: $k}')"
expect 201 "repository registered"
HOST_KEY=$(echo "$BODY" | jq -r .key)
if [ "$HOST_KEY" = "$("$DIMOCLI" pubkey --org "$AVIS")" ]; then
    success "the host's commit key is the #dimo_org the directory publishes: $HOST_KEY"
else
    die "the host's key does not match #dimo_org"
fi

step "DIMO attests Avis as a commercial operator..."
info "Party attributes are DIMO's say-so and live in a table on the host, not in"
info "any org's repository (plan decision E). An operator may hold staff roles,"
info "issue liens and run bookings."
host PUT "/parties/$AVIS" "$DIMO_TOKEN" '{"kind":"org","operator":true}'
expect 200 "Avis is an operator"

# ── Step 2: The fleet ─────────────────────────────────────────────────────

header "Step 2: The fleet: three cars, three tags, the staff"
info "Each vehicle DID has no key of its own. Its document carries a commitment"
info "to its controller; the opening lives in the controller's repository, so"
info "the directory never says who owns the car, and the host can prove it."

CARS=()
n=0
for vin in 1FTFW1E52NFA10001 1FTFW1E52NFA10002 1FTFW1E52NFA10003; do
    n=$((n + 1))
    car=$(create --controller "$AVIS" --alias "vin-$vin.avis.com")
    CARS+=("$car")
    created "car-$n" "$car"
    host PUT "/orgs/$AVIS/network.dimo.org.vehicleControl/$car" "$AVIS_TOKEN" "$(cat "$KEYS/${car#did:dimo:}.control.json")"
    expect 201 "$car: opening committed to Avis's repository"
done
CAR1=${CARS[0]}; CAR2=${CARS[1]}; CAR3=${CARS[2]}
echo ""
step "Control state of car 1 as the directory serves it (era 0, a commitment, no controller):"
curl -s "$DIRECTORY_URL/$CAR1/control" | json

echo ""
step "Tags..."
for slug in fl-fleet ford-pro-enrolled financed-fc; do
    host PUT "/orgs/$AVIS/network.dimo.org.tag/$slug" "$AVIS_TOKEN" "$(jq -cn --arg n "$slug" '{name: $n}')"
    expect 201 "tag $slug"
done
FL_FLEET="at://$AVIS/network.dimo.org.tag/fl-fleet"
FORD_PRO_ENROLLED="at://$AVIS/network.dimo.org.tag/ford-pro-enrolled"
FINANCED_FC="at://$AVIS/network.dimo.org.tag/financed-fc"

echo ""
step "Staff: Carol (admin), Alice (fleet manager), and the booking service..."
info "Members sign in to dauth with their own keys; the host never sees a key."
info "A role is a record like any other, written by the org. Roles are what let"
info "a member write at all: every write takes a live role covering its scope"
info "with the ability the write needs."
CAROL=$(create --alias "carol.avis.com")
ALICE=$(create --alias "alice.avis.com")
BACKEND=$(create --alias "bookings.avis.com")
created "Carol" "$CAROL"
created "Alice" "$ALICE"
created "Avis-bookings" "$BACKEND"

REC=$(role "$AVIS" "$CAROL" '{"inherit":true}' "org:admin,org:members,delegation:create,tag:write")
host POST "/orgs/$AVIS/network.dimo.org.role" "$AVIS_TOKEN" "$REC"
expect 201 "Carol: org:admin, org:members, delegation:create, tag:write over every car (no live abilities, so it commits at once)"
REC=$(role "$AVIS" "$ALICE" "{\"tag\":\"$FL_FLEET\"}" "delegation:create,tag:write,telemetry:read,events:read")
host POST "/orgs/$AVIS/network.dimo.org.role" "$AVIS_TOKEN" "$REC"
expect 201 "Alice: delegation:create, tag:write, telemetry:read, events:read over fl-fleet"

info ""
info "The booking service's role hands out commands, so the org's own write waits"
info "for a second approval (plan decision D): two-person rule as a record fact."
info "The role names the booking commit policy, under which grants of live"
info "abilities to renters do not each wait for two admins (spec §12.5)."
# The abilities are agreement.RentalCatalog().Abilities(): delegation:create
# plus everything the catalog can grant.
REC=$(role "$AVIS" "$BACKEND" '{"inherit":true}' "command:charge,command:lock,command:unlock,delegation:create,events:read,location:precise,telemetry:read" \
        '{"policy":"rental-booking","allowExclusive":true}')
host POST "/orgs/$AVIS/network.dimo.org.role" "$AVIS_TOKEN" "$REC"
expect 202 "booking role parked: $(echo "$BODY" | jq -r '.reasons | join(", ")')"
CAROL_TOKEN=$(signin "$CAROL")
approve "$AVIS" "$(echo "$BODY" | jq -r .pending)" "$CAROL_TOKEN" "Carol approves; the commit carries approvedBy"

echo ""
step "Alice puts the cars in fl-fleet; the org enrolls two with Ford Pro and finances two..."
ALICE_TOKEN=$(signin "$ALICE")
for car in "${CARS[@]}"; do
    REC=$(membership "$FL_FLEET" "$car")
    host POST "/orgs/$AVIS/network.dimo.org.tagMembership" "$ALICE_TOKEN" "$REC"
    expect 201 "$car joined fl-fleet"
done
for car in "$CAR1" "$CAR2"; do
    REC=$(membership "$FORD_PRO_ENROLLED" "$car")
    host POST "/orgs/$AVIS/network.dimo.org.tagMembership" "$AVIS_TOKEN" "$REC"
    expect 201 "$car joined ford-pro-enrolled"
    REC=$(membership "$FINANCED_FC" "$car")
    host POST "/orgs/$AVIS/network.dimo.org.tagMembership" "$AVIS_TOKEN" "$REC"
    expect 201 "$car joined financed-fc"
done

# ── Step 3: Three partners ────────────────────────────────────────────────

header "Step 3: Three partners"

INSURER=$(create --alias "claims.insurer.example")
FORD_CREDIT=$(create --alias "fordcredit.example")
FORD_PRO=$(create --org --org-host "$ORG_HOST_URL" --alias "fordpro.example")
INTEGRATOR=$(create --alias "integrator.example")
created "Insurer" "$INSURER"
created "FordCredit" "$FORD_CREDIT"
created "FordPro" "$FORD_PRO"
created "Integrator" "$INTEGRATOR"
info "The insurer and the lender are plain DIDs; Ford Pro is an org with its own repository."

echo ""
step "The insurer, over fl-fleet, written by Alice..."
info "Inside her role, nothing live: it commits directly. The grant does not"
info "say what happens at a sale, and the default is retainHistory, so a sale"
info "keeps the insurer's Avis-era history."
REC=$(grant "$AVIS" "$INSURER" "{\"tag\":\"$FL_FLEET\"}" "telemetry:read,events:read" fleet-insurance)
host PUT "/orgs/$AVIS/network.dimo.delegation/insurer" "$ALICE_TOKEN" "$REC"
expect 201 "insurer grant committed by Alice"
if [ "$PRESENT" != 1 ] && [ "$ODRL" != 1 ]; then
    # One policy by default; presenter mode offers every one, DEMO_ODRL shows them all.
    info "What Alice sent is an ODRL Agreement; the host committed it with its uid:"
    host GET "/orgs/$AVIS/network.dimo.delegation/insurer" "$ALICE_TOKEN"
    echo "$BODY" | policy
    : >"$WRITTEN"
fi
INSURER_URI="at://$AVIS/network.dimo.delegation/insurer"

echo ""
step "Ford Credit's lien, over financed-fc..."
info "Revocable only by the lender and dropped on transfer. Only an attested"
info "operator may issue such a record, and it waits for a second approval:"
info "the org writes it, Carol approves. The lender could not approve its own."
REC=$(grant "$AVIS" "$FORD_CREDIT" "{\"tag\":\"$FINANCED_FC\"}" "location:precise,health:read" lien \
        '{"dimo:revocableBy":"to","dimo:afterTransfer":"drop"}')
host PUT "/orgs/$AVIS/network.dimo.delegation/fordcredit" "$AVIS_TOKEN" "$REC"
expect 202 "lien parked: $(echo "$BODY" | jq -r '.reasons | join(", ")')"
PENDING=$(echo "$BODY" | jq -r .pending)
FORD_CREDIT_TOKEN=$(signin "$FORD_CREDIT")
host POST "/orgs/$AVIS/pending/$PENDING/approve" "$FORD_CREDIT_TOKEN"
expect 403 "the lender may not approve it: $(echo "$BODY" | jq -r .error)"
approve "$AVIS" "$PENDING" "$CAROL_TOKEN" "Carol approves the lien"
FORD_CREDIT_URI="at://$AVIS/network.dimo.delegation/fordcredit"

echo ""
step "Ford Pro, over ford-pro-enrolled: telemetry plus lock and unlock..."
info "Commands are live abilities; nobody on staff holds them, so the org writes"
info "it as itself and Carol approves. The grant permits one level of attenuated"
info "redelegation, which is how Ford Pro will pass telemetry to its integrator,"
info "and drops at transfer: when Avis sells a car, Ford Pro loses it entirely."
REC=$(grant "$AVIS" "$FORD_PRO" "{\"tag\":\"$FORD_PRO_ENROLLED\"}" "telemetry:read,command:lock,command:unlock" telematics \
        '{"dimo:redelegate":{"mode":"attenuated","maxDepth":1},"dimo:afterTransfer":"drop"}')
host PUT "/orgs/$AVIS/network.dimo.delegation/fordpro" "$AVIS_TOKEN" "$REC"
expect 202 "Ford Pro grant parked: $(echo "$BODY" | jq -r '.reasons | join(", ")')"
approve "$AVIS" "$(echo "$BODY" | jq -r .pending)" "$CAROL_TOKEN" "Carol approves"
FORD_PRO_URI="at://$AVIS/network.dimo.delegation/fordpro"

echo ""
step "Ford Pro registers its own repository and redelegates telemetry to its integrator..."
FORD_PRO_TOKEN=$(signin "$FORD_PRO")
host POST "/orgs/$FORD_PRO" "$FORD_PRO_TOKEN" "$(jq -cn --arg k "$(jq -r .privateKeyBase64 "$KEYS/${FORD_PRO#did:dimo:}.org.json")" '{privateKey: $k}')"
expect 201 "Ford Pro's repository registered"
host PUT "/parties/$FORD_PRO" "$DIMO_TOKEN" '{"kind":"org","operator":true}'
expect 200 "DIMO attests Ford Pro"
REC=$(grant "$FORD_PRO" "$INTEGRATOR" '{"inherit":true}' "telemetry:read" analytics "{\"dimo:basis\":[\"$FORD_PRO_URI\"]}")
host PUT "/orgs/$FORD_PRO/network.dimo.delegation/integrator" "$FORD_PRO_TOKEN" "$REC"
expect 201 "integrator grant committed in Ford Pro's repository, basis = Avis's grant to Ford Pro"
INTEGRATOR_URI="at://$FORD_PRO/network.dimo.delegation/integrator"

pause
echo ""
info "Now the tokens. Each party signs in to dauth, proves possession of its key"
info "with a DPoP proof, and names the delegation, the vehicle and the abilities"
info "it wants. dauth asks the host to authorize and mints what the host"
info "computed: historical abilities carry data windows, live ones carry none."
echo ""
mint "The insurer reads car 1's telemetry and events (historical: windows from the grant's start)" \
    "$INSURER" "$INSURER_URI" "$CAR1" "telemetry:read,events:read"
mint "Ford Credit locates car 2 under its lien" \
    "$FORD_CREDIT" "$FORD_CREDIT_URI" "$CAR2" "location:precise"
mint "Ford Pro locks car 1 (live: no window, a 15-minute token)" \
    "$FORD_PRO" "$FORD_PRO_URI" "$CAR1" "command:lock"
mint "The integrator reads car 1's telemetry through a chain of two repositories" \
    "$INTEGRATOR" "$INTEGRATOR_URI" "$CAR1" "telemetry:read"
refuse not_covered "The integrator asks to lock car 1: Ford Pro attenuated its grant to telemetry" \
    "$INTEGRATOR" "$INTEGRATOR_URI" "$CAR1" "command:lock"
refuse not_covered "The insurer asks about car 3's location: never granted" \
    "$INSURER" "$INSURER_URI" "$CAR3" "location:precise"

echo ""
step "Avis lists who has access to car 1 below its grant to Ford Pro (spec §9.3)..."
host GET "/orgs/$AVIS/delegations/fordpro/descendants?vehicle=$CAR1" "$AVIS_TOKEN"
expect 200 "descendants"
echo "$BODY" | jq '.descendants[] | {uri, to, depth, abilities, coverage: (.coverage | {live, historical: (.historical | keys)})}' | show

# ── Step 4: A booking ─────────────────────────────────────────────────────

header "Step 4: A booking"
info "A renter is not a member and not a partner: they bought a service. The"
info "booking service holds the agreement, whose duties (payment, return,"
info "retention) gate what it compiles to, and after every change writes the"
info "grants it produces as ODRL Agreements, under its constrained role."
info "The host never learns what a booking is (plan decision F)."

RENTER=$(create --alias "renter.example")
ROADSIDE=$(create --alias "roadside.example")
created "Renter" "$RENTER"
created "Roadside" "$ROADSIDE"

BOOKING="bk-$(date +%H%M%S)"
AGREEMENT="$DEMO_DIR/agreement.json"
DUE_BACK=$(iso $((NOW_EPOCH + 2 * 86400)))
jq -n --arg id "$BOOKING" --arg avis "$AVIS" --arg renter "$RENTER" --arg car "$CAR1" --arg backend "$BACKEND" \
    --arg from "$BOOKED_FROM" --arg due "$DUE_BACK" --arg booked "$(iso $((NOW_EPOCH - 7200)))" '
    {"$type": "network.dimo.agreement", id: $id, assigner: $avis, assignee: $renter,
     target: {class: "suv-intermediate", vehicle: $car, assignedAt: $from},
     services: [{code: "rental"}],
     duties: [{action: "compensate", fulfilledAt: $booked},
              {action: "returnVehicle", dueBy: $due},
              {action: "retainData", term: 2592000000000000}],
     window: {from: $from, to: $due},
     state: "paid", timestamps: {bookedAt: $booked},
     terms: "sha256:9f2c", createdBy: $backend}' >"$AGREEMENT"

step "Paid, and car 1 assigned at the desk 40 minutes ago. The booking service syncs the agreement:"
booking
success "two grants under stable keys: custody (commands, exclusive, dies at return) and history (telemetry, kept)"
CUSTODY_URI="at://$AVIS/network.dimo.delegation/$BOOKING:rental:custody"
HISTORY_URI="at://$AVIS/network.dimo.delegation/$BOOKING:rental:history"
ROADSIDE_URI="at://$AVIS/network.dimo.delegation/$BOOKING:roadside:roadside:inc-1"

pause
echo ""
mint "The renter unlocks car 1" "$RENTER" "$CUSTODY_URI" "$CAR1" "command:unlock"
refuse exclusive_hold "Ford Pro tries to lock car 1 while the renter holds it (spec §12.2)" \
    "$FORD_PRO" "$FORD_PRO_URI" "$CAR1" "command:lock"
mint "Ford Pro can still read car 1's telemetry: only the commands are suspended" \
    "$FORD_PRO" "$FORD_PRO_URI" "$CAR1" "telemetry:read"
refuse not_covered "The renter's history before the device has synced a pickup: nothing driven, nothing to read (narrowToCustody)" \
    "$RENTER" "$HISTORY_URI" "$CAR1" "telemetry:read"

pause
echo ""
step "The car's device syncs the pickup (30 minutes ago), and the renter has broken down..."
info "Custody is a fact about the car, written under its own key; the grants are"
info "recommitted. An open incident compiles to a roadside grant for its duration."
jq --arg start "$PICKUP" --arg responder "$ROADSIDE" --arg opened "$INCIDENT_OPENED" '
    .state = "pickedUp" | .custody = [{start: $start}]
    | .services += [{code: "roadside"}]
    | .incidents = [{id: "inc-1", responder: $responder, openedAt: $opened}]' "$AGREEMENT" >"$AGREEMENT.next" && mv "$AGREEMENT.next" "$AGREEMENT"
booking
mint "Roadside locates car 1 while the incident is open" "$ROADSIDE" "$ROADSIDE_URI" "$CAR1" "location:precise"

pause
echo ""
step "The incident closes and the car comes back (10 minutes ago). The device syncs the return..."
info "Custody and roadside drop out of the compilation and are tombstoned by the"
info "booking service; the custody leg closes; history narrows to the drive."
jq --arg end "$RETURN" --arg closed "$INCIDENT_CLOSED" '
    .state = "returned" | .custody[0].end = $end | .incidents[0].closedAt = $closed' "$AGREEMENT" >"$AGREEMENT.next" && mv "$AGREEMENT.next" "$AGREEMENT"
booking

echo ""
refuse revoked "The renter's commands are gone" "$RENTER" "$CUSTODY_URI" "$CAR1" "command:unlock"
refuse revoked "Roadside is done" "$ROADSIDE" "$ROADSIDE_URI" "$CAR1" "location:precise"
mint "Ford Pro gets its car back" "$FORD_PRO" "$FORD_PRO_URI" "$CAR1" "command:lock"
mint "The renter keeps the history of the drive, and nothing else" "$RENTER" "$HISTORY_URI" "$CAR1" "telemetry:read"

# ── Step 5: The sale ──────────────────────────────────────────────────────

header "Step 5: Avis sells car 1"
info "A transfer in the directory starts a new era with a new controller and a"
info "new commitment. No record is touched: every grant's afterTransfer policy"
info "decides what it keeps. drop loses the car; retainHistory keeps the Avis"
info "era's data window and nothing after it."

BUYER=$(create --alias "bob.example")
created "Buyer" "$BUYER"
"$DIMOCLI" transfer -server "$DIRECTORY_URL" --did "$CAR1" --to "$BUYER" | show
SALE_EPOCH=$(date +%s)
sleep 2
step "Car 1's eras now:"
curl -s "$DIRECTORY_URL/$CAR1/control" | jq '.eras | map({number, start, end})' | show

pause
echo ""
refuse not_covered "Ford Credit's lien on car 1 dropped with the transfer" "$FORD_CREDIT" "$FORD_CREDIT_URI" "$CAR1" "location:precise"
mint "Ford Credit still locates car 2, which Avis still finances" "$FORD_CREDIT" "$FORD_CREDIT_URI" "$CAR2" "location:precise"
refuse not_covered "Ford Pro cannot lock a car Avis no longer controls" "$FORD_PRO" "$FORD_PRO_URI" "$CAR1" "command:lock"
refuse not_covered "Nor read it: the partner's grant drops at transfer, so it keeps no history either" \
    "$FORD_PRO" "$FORD_PRO_URI" "$CAR1" "telemetry:read"
refuse not_covered "And the integrator's grant, which narrows Ford Pro's, goes with it" \
    "$INTEGRATOR" "$INTEGRATOR_URI" "$CAR1" "telemetry:read"
mint "The insurer keeps car 1's Avis-era history: the window now ends at the transfer" \
    "$INSURER" "$INSURER_URI" "$CAR1" "telemetry:read"
mint "The renter keeps the drive" "$RENTER" "$HISTORY_URI" "$CAR1" "telemetry:read"

pause
echo ""
step "The buyer starts clean: a repository of their own, the era-1 opening, and a consent to the insurer..."
info "This is spec §13.3: a person granting one app over one car is the same"
info "record and the same issuer path as a fleet. The host generated this"
info "repository's key, so the buyer publishes it as #dimo_org."
BUYER_TOKEN=$(signin "$BUYER")
host PUT "/parties/$BUYER" "$DIMO_TOKEN" '{"kind":"person"}'
expect 200 "DIMO attests the buyer as a person"
host POST "/orgs/$BUYER" "$BUYER_TOKEN"
expect 201 "repository registered with a host-generated key"
"$DIMOCLI" update -server "$DIRECTORY_URL" --did "$BUYER" --org-key "$(echo "$BODY" | jq -r .key)" --org-host "$ORG_HOST_URL" | show
host PUT "/orgs/$BUYER/network.dimo.org.vehicleControl/$CAR1" "$BUYER_TOKEN" "$(cat "$KEYS/${CAR1#did:dimo:}.control.json")"
expect 201 "era-1 opening committed to the buyer's repository"
REC=$(grant "$BUYER" "$INSURER" "{\"vehicle\":\"$CAR1\"}" "telemetry:read" consumer-insurance)
host PUT "/orgs/$BUYER/network.dimo.delegation/insurance" "$BUYER_TOKEN" "$REC"
expect 201 "consent committed"
mint "The insurer reads car 1 under the buyer's consent: the window starts at era 1" \
    "$INSURER" "at://$BUYER/network.dimo.delegation/insurance" "$CAR1" "telemetry:read"

echo ""
step "The buyer also consents to the insurer's claims app, and only through that app..."
info "clientAllowlist names the apps a delegation may be used through (spec §2)."
info "The app attests each request with a short assertion signed by its own DID's"
info "key and bound to the caller's DPoP key, so it cannot be replayed or lent."
CLAIMS_APP=$(create --alias "claims.insurer.example")
created "ClaimsApp" "$CLAIMS_APP"
REC=$(grant "$BUYER" "$INSURER" "{\"vehicle\":\"$CAR1\"}" "telemetry:read" claims '{}' "$CLAIMS_APP")
host PUT "/orgs/$BUYER/network.dimo.delegation/claims" "$BUYER_TOKEN" "$REC"
expect 201 "consent committed, allowlisting the claims app"
mint "The insurer, through the claims app" \
    "$INSURER" "at://$BUYER/network.dimo.delegation/claims" "$CAR1" "telemetry:read" "$CLAIMS_APP"
refuse client_not_allowed "The insurer, directly: no app attested, so the allowlist refuses" \
    "$INSURER" "at://$BUYER/network.dimo.delegation/claims" "$CAR1" "telemetry:read"

# ── Step 6: The data ──────────────────────────────────────────────────────

header "Step 6: The same car, three grants"
info "dq serves telemetry from a DuckLake catalog that din normally fills. Here"
info "a seed tool plays din: a speed reading every two seconds for car 1 over the"
info "last hour, decoded into the lake before dq starts, since the file catalog"
info "has one writer. Every query carries an access token from dauth and a DPoP"
info "proof for the request, and dq clamps the requested range to the token's"
info "windows (spec §11.4). Same car, same data, three grants, three slices."

LAKE="$DEMO_DIR/lake"
mkdir -p "$LAKE/data" "$LAKE/blobs"
step "The buyer drives off. A few seconds of readings under the new owner..."
sleep 6
step "Seeding car 1's telemetry for the last hour, up to now..."
"$BIN/dq-seed" -catalog "$LAKE/catalog.ducklake" -data-path "$LAKE/data" -subject "$CAR1" \
    -from "$VALID_FROM" -every 2s | show

step "Starting dq on :$DQ_PORT over the seeded catalog..."
info "It verifies tokens against dauth's exchange keys and expects audience dq."
DUCKLAKE_CATALOG_DSN="$LAKE/catalog.ducklake" DUCKLAKE_DATA_PATH="$LAKE/data" BLOB_BUCKET="$LAKE/blobs" \
    MATERIALIZER_ENABLED=true MATERIALIZER_POLL_INTERVAL=1s LATEST_KV_READ_MODE=off LAKE_ROLLUP_DAILY_SERVING=true \
    PORT="$DQ_PORT" GRPC_PORT=13001 MON_PORT=18889 DIMO_REGISTRY_CHAIN_ID=137 LOG_LEVEL=info \
    PUBLIC_BASE_URL="$DQ_URL" TOKEN_EXCHANGE_JWK_KEY_SET_URL="$DAUTH_URL/exchange/keys" \
    TOKEN_EXCHANGE_ISSUER_URL="$DAUTH_URL/exchange" TOKEN_AUDIENCE=dq \
    "$BIN/dq" -settings /dev/null >"$DEMO_DIR/dq.log" 2>&1 &
PIDS+=($!)
wait_for "$DQ_URL/" "dq"
BUYER_CONSENT_URI="at://$BUYER/network.dimo.delegation/insurance"
RANGE=$(jq -cn --arg from "$(iso $((NOW_EPOCH - 86400)))" --arg to "$(iso $((NOW_EPOCH + 3600)))" '{from: $from, to: $to}')
step "Checking dq serves the seeded signals..."
for i in $(seq 1 20); do
    PROBE=$("$DIMOCLI" query --dauth "$DAUTH_URL" --dq "$DQ_URL" --did "$INSURER" --grant "$BUYER_CONSENT_URI" --vehicle "$CAR1" \
        --abilities telemetry:read --query "$SIGNALS_QUERY" --variables "$RANGE" 2>&1) || true
    if echo "$PROBE" | jq -e '.signals | length > 0' >/dev/null 2>&1; then
        break
    fi
    [ "$i" -eq 20 ] && die "dq never served the seeded signals; last answer: $PROBE"
    sleep 1
done
success "signals served"
pause
echo ""
info "Everyone asks for the same range, a day before the run to an hour after, in"
info "five-minute buckets of maximum speed. The data runs from $VALID_FROM."
info "The drive was $PICKUP to $RETURN; the sale was at $(iso "$SALE_EPOCH")."
echo ""
query "The renter, under the history grant: only the drive's buckets come back" \
    "$RENTER" "$HISTORY_URI" "$CAR1" "telemetry:read" "$SIGNALS_QUERY" "$RANGE"
query_refused "not covered" "The renter asks for the latest reading: the window closed at return" \
    "$RENTER" "$HISTORY_URI" "$CAR1" "telemetry:read" "$LATEST_QUERY"
query "The insurer under Avis's grant: the whole hour up to the sale, nothing after" \
    "$INSURER" "$INSURER_URI" "$CAR1" "telemetry:read" "$SIGNALS_QUERY" "$RANGE"
query "The insurer under the buyer's consent: only since the sale" \
    "$INSURER" "$BUYER_CONSENT_URI" "$CAR1" "telemetry:read" "$SIGNALS_QUERY" "$RANGE"

# ── Step 7: A proof that survives the host ────────────────────────────────

header "Step 7: The renter's proof, with the host down"
info "A coverage proof is the transcript of one evaluation: every commit it read,"
info "signed by its org's #dimo_org key, plus the era log. Anyone can replay it"
info "against the keys the directory publishes. The host does not have to exist."

RENTER_TOKEN=$(signin "$RENTER")
host GET "/orgs/$AVIS/delegations/$BOOKING:rental:history/proof?vehicle=$CAR1" "$RENTER_TOKEN"
expect 200 "proof fetched ($(echo "$BODY" | jq '.commits | length') commits)"
echo "$BODY" >"$DEMO_DIR/proof.json"
echo "$BODY" | jq '{delegation, at, keys, commits: [.commits[] | "\(.collection)/\(.rkey) \(.op) by \(.committedBy // "the org")"]}' | show

pause
step "Stopping the org host..."
kill "${PIDS[2]}" 2>/dev/null || true
wait "${PIDS[2]}" 2>/dev/null || true
PIDS[2]=""
if curl -sf "$ORG_HOST_URL/health" >/dev/null 2>&1; then die "the org host is still up"; fi
success "org host is down"

step "Verifying the proof against the directory's keys and era log..."
"$DIMOCLI" verify-proof -server "$DIRECTORY_URL" --file "$DEMO_DIR/proof.json" | show
success "the renter can show what they were allowed to read, and when, without asking Avis"

# ── Summary ──────────────────────────────────────────────────────────────

header "Demo complete"

echo -e "  ${DIM}The identifiers behind the names:${NC}"
echo -e "  ${GREEN}Avis:${NC}         $AVIS"
echo -e "  ${GREEN}Cars:${NC}         $CAR1 (sold to $BUYER)"
echo -e "                $CAR2"
echo -e "                $CAR3"
echo -e "  ${GREEN}Insurer:${NC}      $INSURER"
echo -e "  ${GREEN}Ford Credit:${NC}  $FORD_CREDIT"
echo -e "  ${GREEN}Ford Pro:${NC}     $FORD_PRO  →  $INTEGRATOR"
echo -e "  ${GREEN}Renter:${NC}       $RENTER"
echo ""
echo -e "  ${BOLD}What ran:${NC}"
echo -e "    1. An org with a commit key in its DID document and a repository on the host"
echo -e "    2. Vehicles the org controls through commitments; the openings are the org's records"
echo -e "    3. Roles for staff, a two-person rule as a record fact, a constrained booking role"
echo -e "    4. Three partner grants, one redelegated through a second repository"
echo -e "    5. A booking compiled into grants: exclusive custody, roadside for an incident, history kept"
echo -e "    6. A sale: one directory operation, and every grant's own policy decided what it kept"
echo -e "    7. A consumer consent on the same records, and a proof that verifies with the host gone"
echo -e "    8. One car's telemetry queried under three grants, and dq clamped each to its windows"
echo ""
echo -e "  ${BOLD}Every token came from dauth's /exchange, DPoP-bound, carrying what the host computed,${NC}"
echo -e "  ${BOLD}and dq served exactly that.${NC}"
echo ""
