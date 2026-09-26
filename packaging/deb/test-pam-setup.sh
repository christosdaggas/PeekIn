#!/bin/sh
# Camera-free integration check; touches only a private copy of PAM files.
set -eu
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT HUP INT TERM
PAM_DIR="$ROOT"; export PAM_DIR
cp /etc/pam.d/sudo "$ROOT/sudo"
cp /etc/pam.d/gdm-password "$ROOT/gdm-password"
cp "$ROOT/sudo" "$ROOT/sudo.original"
cp "$ROOT/gdm-password" "$ROOT/gdm.original"
SETUP=./packaging/deb/pam-setup

"$SETUP" install
for f in sudo gdm-password; do
    [ "$(grep -c '^auth \[success=done default=ignore\] pam_peekin.so$' "$ROOT/$f")" = 1 ]
    [ "$(grep -n 'pam_peekin.so' "$ROOT/$f" | cut -d: -f1)" -lt "$(grep -n '^@include common-auth$' "$ROOT/$f" | cut -d: -f1)" ]
done
before=$(cksum "$ROOT/sudo" "$ROOT/gdm-password")
"$SETUP" install
[ "$before" = "$(cksum "$ROOT/sudo" "$ROOT/gdm-password")" ]
"$SETUP" remove
cmp "$ROOT/sudo" "$ROOT/sudo.original"
cmp "$ROOT/gdm-password" "$ROOT/gdm.original"

# A required rule after the include must never be skipped by face success.
printf '%s\n' 'auth required pam_custom_gate.so' >> "$ROOT/gdm-password"
before=$(cksum "$ROOT/sudo" "$ROOT/gdm-password")
if "$SETUP" install; then exit 1; fi
[ "$before" = "$(cksum "$ROOT/sudo" "$ROOT/gdm-password")" ]
cp "$ROOT/gdm.original" "$ROOT/gdm-password"

# A login stack without the nologin gate must not be enabled.
awk '$3 != "pam_nologin.so"' "$ROOT/gdm-password" > "$ROOT/gdm.tmp"
mv "$ROOT/gdm.tmp" "$ROOT/gdm-password"
if "$SETUP" install; then exit 1; fi
cp "$ROOT/gdm.original" "$ROOT/gdm-password"

# The package can still be removed if GDM was uninstalled first.
"$SETUP" install
rm "$ROOT/gdm-password"
"$SETUP" remove
cmp "$ROOT/sudo" "$ROOT/sudo.original"
cp "$ROOT/gdm.original" "$ROOT/gdm-password"

# Shared PAM stacks are never edited and must not reference a removed module.
printf '%s\n' 'auth required pam_peekin.so' > "$ROOT/common-auth"
if "$SETUP" remove; then exit 1; fi
grep -q '^auth required pam_peekin.so$' "$ROOT/common-auth"
rm "$ROOT/common-auth"

# Never remove a custom module reference whose semantics we do not know.
printf '%s\n' 'auth required pam_peekin.so debug' >> "$ROOT/sudo"
if "$SETUP" remove; then exit 1; fi
grep -q '^auth required pam_peekin.so debug$' "$ROOT/sudo"
echo DEBIAN_PAM_SETUP_OK
