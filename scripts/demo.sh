#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# DIMO v2 Identity System — End-to-End Demo
#
# Demonstrates the complete flow:
#   Vehicle Owner → Vehicle DID → Device DID (pairing via SACD)
#   → Developer DID → Access Grant → Auth → JWT → Emergency Revocation
#
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
info "This DID will have authority over the vehicle DID."

OWNER_OUTPUT=$($DIMOCLI create \
    -server "$DIRECTORY_URL" \
    -alias "alice.dimo.zone" 2>&1)
echo "$OWNER_OUTPUT"

OWNER_DID=$(echo "$OWNER_OUTPUT" | extract_did)
if [ -z "$OWNER_DID" ]; then fail "Failed to create owner DID"; exit 1; fi
success "Owner DID: $OWNER_DID"

# Get the owner's public key (will be used as rotation key for vehicle DID)
OWNER_PUBKEY=$($DIMOCLI pubkey "$OWNER_DID")
info "Owner public key: $OWNER_PUBKEY"

# ── Step 2: Create Vehicle DID ───────────────────────────────────────────

header "Step 2: Create Vehicle DID (Owned by Vehicle Owner)"
info "The vehicle is a separate DID, but the owner's key is the rotation key."
info "This means the owner can manage the vehicle's identity and SACDs."

VEHICLE_OUTPUT=$($DIMOCLI create \
    -server "$DIRECTORY_URL" \
    -rotation-key "$OWNER_PUBKEY" \
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
info "Instead of an on-chain pairing transaction, the vehicle owner signs"
info "an SACD granting the device permission to write telemetry data."
info "Revoking this SACD = unpairing the device."

$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$VEHICLE_DID" \
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
    -grantor "$VEHICLE_DID" \
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

# ── Step 8: Emergency Revocation ─────────────────────────────────────────

header "Step 8: Emergency Revocation (Vehicle Compromised)"
info "The vehicle owner suspects a security breach."
info "Bumping the SACD epoch invalidates ALL outstanding SACDs at once."
info "Both the device pairing and developer access will be revoked."

step "Current vehicle epoch:"
$DIMOCLI resolve -server "$DIRECTORY_URL" "$VEHICLE_DID" | grep -i epoch || true

echo ""
step "Bumping SACD epoch..."
$DIMOCLI revoke-all -server "$DIRECTORY_URL" -did "$VEHICLE_DID"

echo ""
step "New vehicle epoch:"
$DIMOCLI resolve -server "$DIRECTORY_URL" "$VEHICLE_DID" | grep -i epoch || true

echo ""
step "Verifying device SACD (should FAIL — epoch invalidated)..."
if $DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEVICE_SACD" 2>&1; then
    fail "Device SACD should have been invalidated!"
    exit 1
else
    success "Device SACD correctly invalidated (device unpaired)"
fi

echo ""
step "Verifying developer SACD (should FAIL — epoch invalidated)..."
if $DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEV_SACD" 2>&1; then
    fail "Developer SACD should have been invalidated!"
    exit 1
else
    success "Developer SACD correctly invalidated (access revoked)"
fi

# ── Step 9: Re-grant After Revocation ────────────────────────────────────

header "Step 9: Re-grant Access at New Epoch"
info "After resolving the security issue, the vehicle owner re-grants access."
info "New SACDs are signed at the new epoch."

step "Re-granting device pairing..."
$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$VEHICLE_DID" \
    -grantee "$DEVICE_DID" \
    -permissions "telemetry:write,telemetry:contribute,data:raw" \
    -out "$DEVICE_SACD"

$DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEVICE_SACD"
success "Device re-paired at new epoch"

echo ""
step "Re-granting developer access..."
$DIMOCLI sacd-grant \
    -server "$DIRECTORY_URL" \
    -grantor "$VEHICLE_DID" \
    -grantee "$DEV_DID" \
    -permissions "telemetry:read,telemetry:history,location:approximate" \
    -out "$DEV_SACD"

$DIMOCLI sacd-verify -server "$DIRECTORY_URL" -file "$DEV_SACD"
success "Developer access re-granted at new epoch"

# ── Summary ──────────────────────────────────────────────────────────────

header "Demo Complete"

echo -e "  ${GREEN}Owner DID:${NC}     $OWNER_DID"
echo -e "  ${GREEN}Vehicle DID:${NC}   $VEHICLE_DID"
echo -e "  ${GREEN}Device DID:${NC}    $DEVICE_DID"
echo -e "  ${GREEN}Developer DID:${NC} $DEV_DID"
echo ""
echo -e "  ${BOLD}What we demonstrated:${NC}"
echo -e "    1. Vehicle owner created their DID (passkey-based identity)"
echo -e "    2. Vehicle got its own DID, controlled by the owner's rotation key"
echo -e "    3. Aftermarket device got a DID with metadata (serial, firmware)"
echo -e "    4. Device paired to vehicle via SACD (replaces on-chain pairing)"
echo -e "    5. Developer granted read access via SACD (replaces on-chain privileges)"
echo -e "    6. Developer authenticated and received a JWT with asset permissions"
echo -e "    7. Emergency revocation via epoch bump invalidated ALL SACDs at once"
echo -e "    8. Re-granted access at the new epoch after resolving the issue"
echo ""
echo -e "  ${BOLD}Zero on-chain transactions. Pure cryptographic authorization.${NC}"
echo ""
echo -e "  ${BOLD}${GREEN}This is DIMO v2.${NC}"
echo ""
