#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Sources: a relay writes about a car it holds a grant for
#
# docs/2026-10-24-sources.md, end to end on this machine, all in memory:
#
#   DID directory  (:8082)  DIDs and their keys
#   org host       (:8081)  RentalCo's grants; answers din's /authorize
#   dauth          (:8080)  sign-in by DID (din signs in to call the host)
#   din            (:9443)  ingest over mTLS, into NATS and a local DuckLake
#
# RentalCo owns a car and grants Flespi, a relay, telemetry:write over it.
# Flespi's certificate names its DID. It sends signed CloudEvents: one from a
# tracker it knows by IMEI, one from a machine with a did:key that signs too.
# din checks the signatures and the grant and stores the events as sent. Then
# it refuses an unsigned event, a car with no grant, and, once RentalCo
# revokes, the car itself. At the end the stored rows are read back.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DAUTH_DIR="${DAUTH_DIR:-$PROJECT_DIR/../dauth}"
DIN_DIR="${DIN_DIR:-$PROJECT_DIR/../din}"

DIRECTORY_PORT="${DIRECTORY_PORT:-8082}"
ORG_HOST_PORT="${ORG_HOST_PORT:-8081}"
DAUTH_PORT="${DAUTH_PORT:-8080}"
DIN_PORT="${DIN_PORT:-9443}"
# The services' other listeners; move them when another stack holds the defaults.
DIRECTORY_MON_PORT="${DIRECTORY_MON_PORT:-18888}"
DAUTH_OPS_PORT="${DAUTH_OPS_PORT:-18089}"
DIN_ATTESTATION_PORT="${DIN_ATTESTATION_PORT:-9442}"
DIN_OPS_PORT="${DIN_OPS_PORT:-18080}"
DIRECTORY_URL="http://localhost:$DIRECTORY_PORT"
ORG_HOST_URL="http://localhost:$ORG_HOST_PORT"
DAUTH_URL="http://localhost:$DAUTH_PORT"
DIN_URL="https://localhost:$DIN_PORT"
DAUTH_DID="did:dimo:dauth"

DEMO_DIR="$(mktemp -d "${TMPDIR:-/tmp}/dimo-sources-XXXXXX")"
BIN="$PROJECT_DIR/bin"
DIMOCLI="$BIN/dimocli"
KEYS="$HOME/.dimo/keys"
PIDS=()
DIN_PID=

header()  { echo ""; echo -e "${BOLD}== $1 ==${NC}"; }
step()    { echo -e "  ${YELLOW}>>>  $1${NC}"; }
success() { echo -e "  ${GREEN}[OK]  $1${NC}"; }
fail()    { echo -e "  ${RED}[FAIL]  $1${NC}"; }
info()    { echo -e "  ${CYAN}$1${NC}"; }
show()    { sed 's/^/        /'; }
die()     { fail "$1"; exit 1; }

on_exit() {
    local code=$?
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
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

iso() { date -u -r "$1" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "@$1" +%Y-%m-%dT%H:%M:%SZ; }
NOW_EPOCH=$(date +%s)
NOW=$(iso "$NOW_EPOCH")
VALID_FROM=$(iso $((NOW_EPOCH - 3600)))

wait_for() { # url description [curl flags...]
    local url=$1 what=$2
    shift 2
    for _ in $(seq 1 60); do
        if curl -s -o /dev/null "$@" "$url" 2>/dev/null; then
            success "$what is up"
            return
        fi
        sleep 0.5
    done
    die "$what did not come up at $url"
}

create() {
    local out did
    out=$("$DIMOCLI" create -server "$DIRECTORY_URL" "$@" 2>&1) || { echo "$out" >&2; return 1; }
    did=$(echo "$out" | grep "DID created:" | awk '{print $3}')
    [ -n "$did" ] || { echo "$out" >&2; return 1; }
    echo "$did"
}

signin() { "$DIMOCLI" signin --dauth "$DAUTH_URL" --did "$1" --audience "$ORG_HOST_URL" --scope "${2:-read write}"; }

# host METHOD PATH TOKEN [JSON] — calls the org host; sets STATUS and BODY.
host() {
    local method=$1 path=$2 token=$3 data=${4:-} proof
    proof=$("$DIMOCLI" dpop --token "$token" --method "$method" --url "$ORG_HOST_URL$path")
    local args=(-s -o "$DEMO_DIR/body" -w '%{http_code}' -X "$method"
        -H "Authorization: DPoP $token" -H "DPoP: $proof" -H 'Content-Type: application/json')
    [ -n "$data" ] && args+=(--data-binary "$data")
    STATUS=$(curl "${args[@]}" "$ORG_HOST_URL$path")
    BODY=$(cat "$DEMO_DIR/body")
}

expect() { # status description
    if [ "$STATUS" = "$1" ]; then
        success "$2 ($STATUS)"
    else
        fail "$2: wanted $1, got $STATUS"
        echo "$BODY" | show
        exit 1
    fi
}

# send JSON — the relay posts to din over mTLS with its certificate.
send() {
    STATUS=$(curl -s -o "$DEMO_DIR/body" -w '%{http_code}' --cacert "$DEMO_DIR/ca.pem" \
        --cert "$DEMO_DIR/relay.pem" --key "$DEMO_DIR/relay.key" \
        -H 'Content-Type: application/json' --data-binary "$1" "$DIN_URL/")
    BODY=$(cat "$DEMO_DIR/body")
}

# pem DID — a keystore key as a PEM file, for services that take one.
pem() {
    local out="$DEMO_DIR/${1#did:dimo:}.pem"
    { echo "-----BEGIN PRIVATE KEY-----"; jq -r .privateKeyBase64 "$KEYS/${1#did:dimo:}.json" | fold -w 64; echo "-----END PRIVATE KEY-----"; } >"$out"
    echo "$out"
}

# write_grant FROM TO VEHICLE — an ODRL Agreement letting TO write telemetry
# about VEHICLE from an hour ago on. It has no purpose: writing is not a use.
write_grant() {
    jq -cn --arg from "$1" --arg to "$2" --arg vehicle "$3" --arg from_when "$VALID_FROM" --arg now "$NOW" '
        {"@context": ["http://www.w3.org/ns/odrl.jsonld", "https://schema.dimo.zone/odrl/v1"],
         "@type": "Agreement", profile: "https://schema.dimo.zone/odrl/v1",
         assigner: $from, assignee: $to,
         permission: [{target: $vehicle, "@type": "Asset", action: ["dimo:telemetry.write"],
             constraint: [{leftOperand: "dateTime", operator: "gteq", rightOperand: $from_when}]}],
         "dcterms:issued": $now}'
}

STATUS_DATA() { # a status payload in DIMO's default format, verbatim bytes
    printf '{"signals": [ {"name":"speed","timestamp":"%s","value":%s} ]}' "$NOW" "$1"
}

# ── Services ──────────────────────────────────────────────────────────────

header "Starting the services"
for port in "$DIRECTORY_PORT" "$ORG_HOST_PORT" "$DAUTH_PORT" "$DIN_PORT" \
    "$DIRECTORY_MON_PORT" "$DAUTH_OPS_PORT" "$DIN_ATTESTATION_PORT" "$DIN_OPS_PORT"; do
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
        die "port $port is in use; stop what is listening there or set DIRECTORY_PORT, ORG_HOST_PORT, DAUTH_PORT, DIN_PORT, DIRECTORY_MON_PORT, DAUTH_OPS_PORT, DIN_ATTESTATION_PORT or DIN_OPS_PORT"
    fi
done

step "Building did-directory, org-host, dimocli, dauth and din..."
mkdir -p "$BIN"
(cd "$PROJECT_DIR" && go build -o "$BIN/did-directory" ./cmd/did-directory && go build -o "$BIN/org-host" ./cmd/org-host && go build -o "$DIMOCLI" ./cmd/dimocli)
(cd "$DAUTH_DIR" && go build -o "$BIN/dauth" ./cmd/dauth)
(cd "$DIN_DIR" && CGO_ENABLED=1 go build -o "$BIN/din" ./cmd/din)
success "built into $BIN"

DATABASE_URL="" PORT="$DIRECTORY_PORT" MONITORING_PORT="$DIRECTORY_MON_PORT" LOG_LEVEL=warn \
    "$BIN/did-directory" -settings /dev/null >"$DEMO_DIR/directory.log" 2>&1 &
PIDS+=($!)
wait_for "$DIRECTORY_URL/health" "directory" -f

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEMO_DIR/signin.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$DEMO_DIR/exchange.pem" 2>/dev/null
DATABASE_URL="" ENVIRONMENT=local LOG_LEVEL=info \
    HTTP_ADDRESS="127.0.0.1:$DAUTH_PORT" OPS_ADDRESS="127.0.0.1:$DAUTH_OPS_PORT" \
    PUBLIC_BASE_URL="$DAUTH_URL" DIRECTORY_URL="$DIRECTORY_URL" \
    SIGNIN_ISSUER="$DAUTH_URL/signin" JWT_AUDIENCE=dimo TOKEN_TTL=1h \
    SIGNIN_SIGNING_KEY_1="$(cat "$DEMO_DIR/signin.pem")" \
    EXCHANGE_ISSUER="$DAUTH_URL/exchange" EXCHANGE_AUDIENCE=dq \
    EXCHANGE_SIGNING_KEY_1="$(cat "$DEMO_DIR/exchange.pem")" \
    ORG_HOST_URL="$ORG_HOST_URL" DAUTH_DID="$DAUTH_DID" \
    "$BIN/dauth" >"$DEMO_DIR/dauth.log" 2>&1 &
PIDS+=($!)
wait_for "$DAUTH_URL/signin/keys" "dauth" -f

step "din gets a DID of its own: it signs in to dauth as that DID to ask the org host..."
DIN_DID=$(create --alias "din.dimo.zone")
info "din: $DIN_DID"
DIMO=$(create --alias "dimo.zone")

info "The org host lets dauth and din call /authorize."
DATABASE_URL="" PORT="$ORG_HOST_PORT" LOG_LEVEL=info DIRECTORY_URL="$DIRECTORY_URL" \
    IDENTITY_JWKS_URL="$DAUTH_URL/signin/keys" IDENTITY_ISSUER="$DAUTH_URL/signin" IDENTITY_AUDIENCE="$ORG_HOST_URL" \
    ISSUER_DIDS="$DAUTH_DID,$DIN_DID" ADMIN_DIDS="$DIMO" CONTROL_CACHE_TTL=1s \
    "$BIN/org-host" -settings /dev/null >"$DEMO_DIR/org-host.log" 2>&1 &
PIDS+=($!)
wait_for "$ORG_HOST_URL/health" "org host" -f

# ── Step 1: the car and the relay ─────────────────────────────────────────

header "Step 1: RentalCo's car, and Flespi, a relay"
RENTAL_CO=$(create --org --org-host "$ORG_HOST_URL" --alias "rentalco.example")
info "RentalCo: $RENTAL_CO"
RENTAL_CO_TOKEN=$(signin "$RENTAL_CO")
RENTAL_CO_ORG_KEY=$(jq -r .privateKeyBase64 "$KEYS/${RENTAL_CO#did:dimo:}.org.json")
host POST "/orgs/$RENTAL_CO" "$(signin "$RENTAL_CO" approve)" "$(jq -cn --arg k "$RENTAL_CO_ORG_KEY" '{privateKey: $k}')"
expect 201 "RentalCo's repository registered"

CAR=$(create --controller "$RENTAL_CO" --alias "vin-1FTFW1E52NFA10001.rentalco.example")
host PUT "/orgs/$RENTAL_CO/network.dimo.org.vehicleControl/$CAR" "$RENTAL_CO_TOKEN" "$(cat "$KEYS/${CAR#did:dimo:}.control.json")"
expect 201 "car $CAR, controlled by RentalCo"
OTHER_CAR=$(create --controller "$RENTAL_CO" --alias "vin-1FTFW1E52NFA10002.rentalco.example")
host PUT "/orgs/$RENTAL_CO/network.dimo.org.vehicleControl/$OTHER_CAR" "$RENTAL_CO_TOKEN" "$(cat "$KEYS/${OTHER_CAR#did:dimo:}.control.json")"
expect 201 "a second car, $OTHER_CAR, that Flespi gets no grant for"

FLESPI=$(create --alias "flespi.example")
info "Flespi: $FLESPI, a plain DID with a #signing key"

step "RentalCo grants Flespi telemetry:write over the car..."
info "A delegation like any other. It names no machine and no connection."
host PUT "/orgs/$RENTAL_CO/network.dimo.delegation/flespi" "$RENTAL_CO_TOKEN" "$(write_grant "$RENTAL_CO" "$FLESPI" "$CAR")"
expect 201 "grant written"
GRANT=$(echo "$BODY" | jq -r .uri)
info "$GRANT"

# ── Step 2: din ───────────────────────────────────────────────────────────

header "Step 2: din, and Flespi's certificate"
step "DIMO's CA issues Flespi a client certificate with its DID as a URI SAN..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -keyout "$DEMO_DIR/ca.key" -out "$DEMO_DIR/ca.pem" -subj "/CN=DIMO demo CA" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$DEMO_DIR/din.key" \
    -out "$DEMO_DIR/din.csr" -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in "$DEMO_DIR/din.csr" -CA "$DEMO_DIR/ca.pem" -CAkey "$DEMO_DIR/ca.key" -CAcreateserial \
    -days 1 -out "$DEMO_DIR/din.pem" -extfile <(printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth') 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$DEMO_DIR/relay.key" \
    -out "$DEMO_DIR/relay.csr" -subj "/CN=Flespi ingest" 2>/dev/null
openssl x509 -req -in "$DEMO_DIR/relay.csr" -CA "$DEMO_DIR/ca.pem" -CAkey "$DEMO_DIR/ca.key" -CAcreateserial \
    -days 1 -out "$DEMO_DIR/relay.pem" -extfile <(printf 'subjectAltName=URI:%s\nextendedKeyUsage=clientAuth' "$FLESPI") 2>/dev/null
openssl x509 -in "$DEMO_DIR/relay.pem" -noout -ext subjectAltName | show

step "Starting din: embedded NATS, a local lake, sources on..."
DIN_KEY=$(pem "$DIN_DID")
LOG_LEVEL=info NATS_MODE=embedded NATS_STORE_DIR="$DEMO_DIR/nats" \
    DUCKLAKE_CATALOG_DSN="$DEMO_DIR/lake/meta.ducklake" DUCKLAKE_DATA_PATH="$DEMO_DIR/lake/data" \
    BLOB_BUCKET="$DEMO_DIR/blobs" SINK_MAX_AGE=1s SINK_MAX_AGE_HARD=2s \
    NATS_STREAM_MAX_BYTES=268435456 SIGNALS_MAX_BYTES=268435456 EVENTS_MAX_BYTES=268435456 \
    DIS_CONNECTION_ADDRESS="127.0.0.1:$DIN_PORT" DIS_ATTESTATION_ADDRESS="127.0.0.1:$DIN_ATTESTATION_PORT" OPS_ADDRESS="127.0.0.1:$DIN_OPS_PORT" \
    TLS_CERT_FILE="$DEMO_DIR/din.pem" TLS_KEY_FILE="$DEMO_DIR/din.key" TLS_CA_CERT_FILE="$DEMO_DIR/ca.pem" \
    RPC_URL=http://127.0.0.1:1 \
    TOKEN_EXCHANGE_ISSUER_URL="$DAUTH_URL/exchange" TOKEN_EXCHANGE_JWK_KEY_SET_URL="$DAUTH_URL/signin/keys" \
    VEHICLE_NFT_ADDRESS=0xbA5738a18d83D41847dfFbDC6101d37C69c9B0cF \
    AFTERMARKET_NFT_ADDRESS=0x9c94C395cBcBDe662235E0A9d3bB87Ad708561BA \
    SYNTHETIC_NFT_ADDRESS=0x4804e8D1661cd1a1e5dDdE1ff458A7f878c0aC6D \
    SOURCES_ORG_HOST_URL="$ORG_HOST_URL" SOURCES_DIRECTORY_URL="$DIRECTORY_URL" SOURCES_DAUTH_URL="$DAUTH_URL" \
    SOURCES_DID="$DIN_DID" SOURCES_KEY_FILE="$DIN_KEY" SOURCES_GRANT_TTL=2s \
    "$BIN/din" >"$DEMO_DIR/din.log" 2>&1 &
DIN_PID=$!
PIDS+=($DIN_PID)
wait_for "http://127.0.0.1:$DIN_OPS_PORT/ready" "din" -f

# ── Step 3: Flespi sends ──────────────────────────────────────────────────

header "Step 3: Flespi sends"
step "A tracker Flespi knows by IMEI: Flespi labels it and signs alone..."
EVENT=$("$DIMOCLI" event --did "$FLESPI" --subject "$CAR" --producer "imei:356938035643809" --data "$(STATUS_DATA 42)")
echo "$EVENT" | jq '{source, producer, subject, type, time, sourcesignature}' | show
send "$EVENT"
expect 200 "din stored it"
IMEI_ID=$(echo "$EVENT" | jq -r .id)

step "A machine with a did:key of its own: it signs, and so does Flespi..."
EVENT=$("$DIMOCLI" event --did "$FLESPI" --subject "$CAR" --machine-key "$DEMO_DIR/machine.pem" --data "$(STATUS_DATA 61)")
echo "$EVENT" | jq '{producer, sourcesignature, producersignature}' | show
send "$EVENT"
expect 200 "din stored it"
MACHINE_ID=$(echo "$EVENT" | jq -r .id)

# ── Step 4: refusals ──────────────────────────────────────────────────────

header "Step 4: what din refuses"
step "The same event with the machine's signature stripped..."
# sed, not jq: jq would re-encode data, and any change to its bytes breaks
# both signatures before the header is even looked at.
send "$(echo "$EVENT" | sed -E 's/"producersignature":"[^"]*",//')"
expect 403 "a machine DID named as producer must sign"
echo "$BODY" | show

step "A signed event moved to another time..."
send "$(echo "$EVENT" | sed -E 's/"time":"[^"]*"/"time":"2026-01-01T00:00:00Z"/')"
expect 403 "the signatures cover the header"

step "The other car, which RentalCo never granted..."
send "$("$DIMOCLI" event --did "$FLESPI" --subject "$OTHER_CAR" --producer "imei:356938035643809" --data "$(STATUS_DATA 7)")"
expect 403 "no grant covers it"
echo "$BODY" | show

step "Flespi claiming to be someone else..."
send "$("$DIMOCLI" event --did "$RENTAL_CO" --subject "$CAR" --producer "imei:1" --data "$(STATUS_DATA 1)")"
expect 403 "source must be the certificate's DID"

step "RentalCo revokes the grant..."
host DELETE "/orgs/$RENTAL_CO/network.dimo.delegation/flespi" "$RENTAL_CO_TOKEN"
expect 200 "revoked"
info "din reuses an answer for SOURCES_GRANT_TTL (2s here), so a revocation lands within that."
sleep 3
send "$("$DIMOCLI" event --did "$FLESPI" --subject "$CAR" --producer "imei:356938035643809" --data "$(STATUS_DATA 50)")"
expect 403 "the car is no longer Flespi's to write about"

# ── Step 5: what was stored ───────────────────────────────────────────────

header "Step 5: what the lake holds"
step "Stopping din so its sink drains and the catalog is free to read..."
sleep 3
kill "$DIN_PID" && wait "$DIN_PID" 2>/dev/null || true
duckdb -json -c "INSTALL ducklake; LOAD ducklake;
    ATTACH 'ducklake:$DEMO_DIR/lake/meta.ducklake' AS lake (READ_ONLY);
    SELECT id, source, producer, subject, type, data, extras FROM lake.raw_events ORDER BY \"time\", id;" \
    >"$DEMO_DIR/rows.json"
ROWS=$(jq length "$DEMO_DIR/rows.json")
[ "$ROWS" = 2 ] || { jq . "$DEMO_DIR/rows.json" | show; die "wanted 2 rows, got $ROWS"; }
success "two rows: the two events din took"
jq '.[] | {id, producer, data, extras: (.extras | fromjson)}' "$DEMO_DIR/rows.json" | show
for id in "$IMEI_ID" "$MACHINE_ID"; do
    grant=$(jq -r --arg id "$id" '.[] | select(.id == $id) | .extras | fromjson | .grant' "$DEMO_DIR/rows.json")
    [ "$grant" = "$GRANT" ] || die "$id: grant is $grant, wanted $GRANT"
done
success "each row names the grant that let it in, and keeps the data and signatures as sent"

echo ""
echo -e "${GREEN}${BOLD}Done.${NC}"
