#!/bin/sh
# Inspect systemd's offline start transaction; never start a real service.
set -eu
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/peekin-models.service
TMP=$(mktemp -d /tmp/opencode/peekin-models-test.XXXXXX)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

# A harmless executable lets verification run before PeekIn is installed.
sed 's|^ExecStart=.*|ExecStart=/usr/bin/true|' "$SOURCE" > "$TMP/peekin-models.service"
chmod 644 "$TMP/peekin-models.service"
verify() {
    SYSTEMD_LOG_LEVEL=debug systemd-analyze verify --man=no "$@" > "$TMP/verify.log" 2>&1 || {
        cat "$TMP/verify.log"
        exit 1
    }
}

verify "$TMP/peekin-models.service"
grep -q 'peekin-models.service: Installed new job peekin-models.service/start' "$TMP/verify.log"
if grep -Eq '(tpm2.target|dev-tpmrm0.device): Installed new job' "$TMP/verify.log"; then
    echo 'FAIL: PeekIn pulls in TPM discovery on a system without a TPM' >&2
    exit 1
fi
grep -q 'After: tpm2.target' "$TMP/verify.log"
grep -q 'Before: systemd-user-sessions.service' "$TMP/verify.log"

# Simulate firmware-triggered TPM discovery being requested by another unit.
# PeekIn must retain the ordering, without disabling or masking TPM support.
cat > "$TMP/peekin-tpm-test.target" <<'EOF'
[Unit]
Description=Private TPM discovery transaction fixture
Wants=peekin-models.service tpm2.target
After=peekin-models.service tpm2.target
EOF
verify "$TMP/peekin-tpm-test.target"
grep -q 'tpm2.target: Installed new job tpm2.target/start' "$TMP/verify.log"
grep -q 'dev-tpmrm0.device: Installed new job dev-tpmrm0.device/start' "$TMP/verify.log"
echo DEBIAN_MODELS_SERVICE_OK
