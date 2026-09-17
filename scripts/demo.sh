#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# DIMO v2 Identity System — End-to-End Demo
#
# Demonstrates the complete flow:
#   Owner DID → Vehicle DID (controlled, no signing key) → Device DID
#   (pairing SACD signed by the owner) → Developer access → Auth → JWT
#   → Compromise window (revoke-since) → Sale (transfer to a new era)
#
# The vehicle never signs anything. Its controller of record signs as itself,
# and the vehicle document only carries a commitment to who that is.
# Zero on-chain transactions. Pure DID + SACD + signature verification.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

DIRECTORY_URL="${DIRECTORY_URL:-http://localhost:8080}"
AUTH_URL="${AUTH_URL:-http://localhost:8081}"
export DIMO_VERBOSE=1
DIMOCLI="${DIMOCLI:-}"
DEVICE_SACD=$(mktemp /tmp/sacd-device-XXXXXX.json)
DEV_SACD=$(mktemp /tmp/sacd-dev-XXXXXX.json)

cleanup() {
    rm -f "$DEVICE_SACD" "$DEV_SACD"
}
trap cleanup EXIT

header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

step() {
    echo -e "  ${YELLOW}>>>  $1${NC}"
}

success() {
    echo -e "  ${GREEN}[OK]  $1${NC}"
}

fail() {
    echo -e "  ${RED}[FAIL]  $1${NC}"
}

info() {
    echo -e "  ${CYAN}$1${NC}"
}

extract_did() {
    grep "DID created:" | awk '{print $3}'
}

# ── Step 0: Prerequisites ────────────────────────────────────────────────

header "Step 0: Checking Prerequisites"

if [ -n "$DIMOCLI" ] && [ -x "$DIMOCLI" ]; then
    step "Using dimocli at $DIMOCLI"
elif command -v dimocli &>/dev/null; then
    DIMOCLI="dimocli"
    step "Found dimocli in PATH"
else
    step "Building dimocli from source..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    DIMOCLI="$PROJECT_DIR/bin/dimocli"
    mkdir -p "$PROJECT_DIR/bin"
    (cd "$PROJECT_DIR" && go build -o "$DIMOCLI" ./cmd/dimocli)
    success "Built dimocli at $DIMOCLI"
fi

step "Checking directory at $DIRECTORY_URL..."
for i in $(seq 1 30); do
    if curl -sf "$DIRECTORY_URL/health" > /dev/null 2>&1; then
        success "Directory is healthy"
        break
    fi
    if [ "$i" -eq 30 ]; then fail "Directory not available"; exit 1; fi
    sleep 2
done

step "Checking auth service at $AUTH_URL..."
for i in $(seq 1 30); do
    if curl -sf "$AUTH_URL/health" > /dev/null 2>&1; then
        success "Auth service is healthy"
        break
    fi
    if [ "$i" -eq 30 ]; then fail "Auth service not available"; exit 1; fi
    sleep 2
done

# ── Step 1: Create Vehicle Owner DID ─────────────────────────────────────

header "Step 1: Create Vehicle Owner DID"
info "The vehicle owner is a person (identified by a passkey/secp256r1 key)."
info "This DID will be the vehicle's controller of record."

OWNER_OUTPUT=$($DIMOCLI create \
    -server "$DIRECTORY_URL" \
    -alias "alice.dimo.zone" 2>&1)
echo "$OWNER_OUTPUT"

OWNER_DID=$(echo "$OWNER_OUTPUT" | extract_did)
if [ -z "$OWNER_DID" ]; then fail "Failed to create owner DID"; exit 1; fi
success "Owner DID: $OWNER_DID"

# ── Step 2: Create Vehicle DID ───────────────────────────────────────────

header "Step 2: Create Vehicle DID (Controlled by the Owner)"
info "The vehicle DID has no signing key. A per-vehicle custody key held by the"
info "owner authorizes identity updates, and the document carries only a hash"
info "commitment to the controller, so the owner is not published."

VEHICLE_OUTPUT=$($DIMOCLI create \
    -server "$DIRECTORY_URL" \
    -controller "$OWNER_DID" \
    -alias "vin-1HGCM82633A004352.dimo.zone" \
    -service "storage=DimoStorageNode:https://node7.dimo.zone" 2>&1)
echo "$VEHICLE_OUTPUT"

VEHICLE_DID=$(echo "$VEHICLE_OUTPUT" | extract_did)
if [ -z "$VEHICLE_DID" ]; then fail "Failed to create vehicle DID"; exit 1; fi
success "Vehicle DID: $VEHICLE_DID"

echo ""
step "Vehicle DID Document:"
$DIMOCLI resolve -server "$DIRECTORY_URL" "$VEHICLE_DID"

# ── Step 3: Create Device DID ────────────────────────────────────────────

header "Step 3: Create Aftermarket Device DID"
info "The device (e.g., AutoPi OBD-II dongle) gets its own DID."
info "Device metadata (serial, firmware, type) lives in the DID document."

DEVICE_OUTPUT=$($DIMOCLI create \
    -server "$DIRECTORY_URL" \
    -alias "serial:AP-2024-00847.dimo.zone" \
    -service "metadata=DeviceInfo:firmware-v2.4.1/type-obd2/manufacturer-autopi" 2>&1)
echo "$DEVICE_OUTPUT"

DEVICE_DID=$(echo "$DEVICE_OUTPUT" | extract_did)
if [ -z "$DEVICE_DID" ]; then fail "Failed to create device DID"; exit 1; fi
success "Device DID: $DEVICE_DID"

# ── Step 4: Pair Device to Vehicle (via SACD) ────────────────────────────

header "Step 4: Pair Device to Vehicle via SACD"
info "Instead of an on-chain pairing transaction, the owner (not the vehicle)"
info "signs an SACD over the vehicle granting the device permission to write"
info "telemetry. The SACD carries a proof that the owner controls the vehicle."

$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$OWNER_DID" \
    -asset "$VEHICLE_DID" \
    -grantee "$DEVICE_DID" \
    -permissions "telemetry:write,telemetry:contribute,data:raw" \
    -out "$DEVICE_SACD"

echo ""
step "Device SACD (replaces on-chain pairing):"
python3 -m json.tool < "$DEVICE_SACD" 2>/dev/null || cat "$DEVICE_SACD"

echo ""
step "Verifying device SACD..."
$DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEVICE_SACD"
success "Device is now paired to vehicle via SACD"

# ── Step 5: Create Developer DID ─────────────────────────────────────────

header "Step 5: Create Developer DID"
info "A third-party app developer who wants to access vehicle telemetry."

DEV_OUTPUT=$($DIMOCLI create \
    -server "$DIRECTORY_URL" \
    -alias "dev.example-fleet-app.com" 2>&1)
echo "$DEV_OUTPUT"

DEV_DID=$(echo "$DEV_OUTPUT" | extract_did)
if [ -z "$DEV_DID" ]; then fail "Failed to create developer DID"; exit 1; fi
success "Developer DID: $DEV_DID"

# ── Step 6: Grant Developer Access (via SACD) ────────────────────────────

header "Step 6: Grant Developer Read Access via SACD"
info "Vehicle owner grants the developer permission to read telemetry."

$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$OWNER_DID" \
    -asset "$VEHICLE_DID" \
    -grantee "$DEV_DID" \
    -permissions "telemetry:read,telemetry:history,location:approximate" \
    -out "$DEV_SACD"

echo ""
step "Developer SACD:"
python3 -m json.tool < "$DEV_SACD" 2>/dev/null || cat "$DEV_SACD"

echo ""
step "Verifying developer SACD..."
$DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEV_SACD"
success "Developer access granted"

# ── Step 7: Developer Authenticates → Gets JWT ───────────────────────────

header "Step 7: Developer Authenticates and Gets JWT"
info "Developer presents their signed challenge + SACD to the auth service."
info "Auth service verifies everything and returns a short-lived JWT."

AUTH_OUTPUT=$($DIMOCLI auth \
    -auth-url "$AUTH_URL" \
    -did "$DEV_DID" \
    -sacd "$DEV_SACD" \
    -audience "demo-fleet-app" 2>&1)
echo "$AUTH_OUTPUT"
success "JWT issued — developer can now query telemetry-api"

# ── Step 8: Compromise Window ────────────────────────────────────────────

header "Step 8: Compromise Window (Custody Key Suspected Stolen)"
info "The owner records a revocation window starting before the grants were"
info "issued and rotates the custody key in the same operation. Grants issued"
info "inside the window are invalid; grants issued afterwards are valid again."

sleep 1
COMPROMISE_SINCE=$(date -u -v-1H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)
$DIMOCLI revoke-since -server "$DIRECTORY_URL" -did "$VEHICLE_DID" -since "$COMPROMISE_SINCE"

echo ""
step "Vehicle control state:"
curl -s "$DIRECTORY_URL/$VEHICLE_DID/control" | python3 -m json.tool 2>/dev/null || true

echo ""
step "Verifying device SACD (should FAIL — issued inside the window)..."
if $DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEVICE_SACD" 2>&1; then
    fail "Device SACD should have been invalidated!"
    exit 1
else
    success "Device SACD correctly invalidated (device unpaired)"
fi

sleep 1
echo ""
step "Re-pairing the device after the window..."
$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$OWNER_DID" \
    -asset "$VEHICLE_DID" \
    -grantee "$DEVICE_DID" \
    -permissions "telemetry:write,telemetry:contribute,data:raw" \
    -out "$DEVICE_SACD"
$DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEVICE_SACD"
success "Device re-paired"

# ── Step 9: Sale (Transfer of Control) ───────────────────────────────────

header "Step 9: Sell the Vehicle (New Control Era)"
info "A transfer starts a new era with a new controller and custody key."
info "Grants from the previous era stop working; the buyer starts clean."

BUYER_OUTPUT=$($DIMOCLI create -server "$DIRECTORY_URL" -alias "bob.dimo.zone" 2>&1)
echo "$BUYER_OUTPUT"
BUYER_DID=$(echo "$BUYER_OUTPUT" | extract_did)
if [ -z "$BUYER_DID" ]; then fail "Failed to create buyer DID"; exit 1; fi
success "Buyer DID: $BUYER_DID"

echo ""
$DIMOCLI transfer -server "$DIRECTORY_URL" -did "$VEHICLE_DID" -to "$BUYER_DID"

echo ""
step "Verifying the previous owner's device SACD (should FAIL — previous era)..."
if $DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEVICE_SACD" 2>&1; then
    fail "Previous-era SACD should be invalid!"
    exit 1
else
    success "Previous-era SACD correctly invalid"
fi

echo ""
step "Previous owner tries to grant again (should FAIL — no longer controller)..."
if $DIMOCLI sacd-grant -server "$DIRECTORY_URL" -grantor "$OWNER_DID" -asset "$VEHICLE_DID" \
    -grantee "$DEV_DID" -permissions "telemetry:read" -out "$DEV_SACD" 2>&1; then
    fail "Previous owner should not be able to grant!"
    exit 1
else
    success "Previous owner correctly refused"
fi

echo ""
step "Buyer grants the developer access in the new era..."
$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$BUYER_DID" \
    -asset "$VEHICLE_DID" \
    -grantee "$DEV_DID" \
    -permissions "telemetry:read,telemetry:history,location:approximate" \
    -out "$DEV_SACD"
$DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEV_SACD"
success "Buyer's grant is valid"

# ── Summary ──────────────────────────────────────────────────────────────

header "Demo Complete"

echo -e "  ${GREEN}Owner DID:${NC}     $OWNER_DID"
echo -e "  ${GREEN}Buyer DID:${NC}     $BUYER_DID"
echo -e "  ${GREEN}Vehicle DID:${NC}   $VEHICLE_DID"
echo -e "  ${GREEN}Device DID:${NC}    $DEVICE_DID"
echo -e "  ${GREEN}Developer DID:${NC} $DEV_DID"
echo ""
echo -e "  ${BOLD}What we demonstrated:${NC}"
echo -e "    1. Vehicle owner created their DID (passkey-based identity)"
echo -e "    2. Vehicle got a DID with no signing key and a private controller commitment"
echo -e "    3. Aftermarket device got a DID with metadata (serial, firmware)"
echo -e "    4. Owner (never the vehicle) paired the device via SACD with a control proof"
echo -e "    5. Developer granted read access via SACD (replaces on-chain privileges)"
echo -e "    6. Developer authenticated and received a JWT with asset permissions"
echo -e "    7. Compromise window invalidated grants issued inside it; re-grant works after"
echo -e "    8. Sale started a new era: old grants and the old owner lost authority"
echo ""
echo -e "  ${BOLD}Zero on-chain transactions. Pure cryptographic authorization.${NC}"
echo ""
echo -e "  ${BOLD}${GREEN}This is DIMO v2.${NC}"
echo ""
