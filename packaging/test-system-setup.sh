#!/bin/sh
set -eu
ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT
# Never reach the installed authselect setup (and so the live authselect
# selection) from this test, even on a machine where PeekIn is installed.
export PAM_SETUP="$ROOT/no-pam-setup"
export SERVICE_USER=peekin-test-nonexistent
# Never read a real linux-hello installation, nor run an installed PeekIn,
# from this test.
export PEEKIN_CLI="$ROOT/no-peekin"
export OLD_ETC="$ROOT/no-old-etc" OLD_ACTIVITY="$ROOT/no-old-activity" OLD_SNAPSHOTS="$ROOT/no-old-log"
mkdir -p "$ROOT/pam"
cat > "$ROOT/pam/sudo" <<'EOF'
#%PAM-1.0
auth required pam_env.so
auth sufficient pam_unix.so
auth required pam_deny.so
account include system-auth
EOF
cat > "$ROOT/pam/gdm-password" <<'EOF'
auth required pam_selinux_permit.so
auth required pam_env.so
auth sufficient pam_unix.so
auth required pam_deny.so
account required pam_nologin.so
EOF
PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install
[ "$(grep -c pam_peekin "$ROOT/pam/sudo")" = 1 ]
[ "$(grep -c pam_peekin "$ROOT/pam/gdm-password")" = 1 ]
grep -q '^auth required pam_env.so$' "$ROOT/pam/sudo"
[ "$(grep -n pam_peekin "$ROOT/pam/sudo" | cut -d: -f1)" -gt "$(grep -n pam_env.so "$ROOT/pam/sudo" | cut -d: -f1)" ]
[ "$(grep -n pam_peekin "$ROOT/pam/sudo" | cut -d: -f1)" -lt "$(grep -n pam_unix.so "$ROOT/pam/sudo" | cut -d: -f1)" ]
PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install
[ "$(grep -c pam_peekin "$ROOT/pam/sudo")" = 1 ]
PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup remove
! grep -q pam_peekin "$ROOT/pam/sudo"
! grep -q pam_peekin "$ROOT/pam/gdm-password"
cp /dev/null "$ROOT/pam/sudo"
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install; then
    echo 'unsupported layout was accepted' >&2; exit 1
fi
# Included stacks and custom existing rules are rejected before either file changes.
cat > "$ROOT/pam/sudo" <<'EOF'
auth include system-auth
EOF
before=$(cksum "$ROOT/pam/gdm-password")
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install; then
    echo 'included stack was accepted' >&2; exit 1
fi
[ "$before" = "$(cksum "$ROOT/pam/gdm-password")" ]

# A post-password auth module would be skipped by biometric success, so reject
# the whole transaction before changing either service.
cat > "$ROOT/pam/sudo" <<'EOF'
auth required pam_env.so
auth sufficient pam_unix.so
auth required pam_custom_gate.so
auth required pam_deny.so
EOF
cat > "$ROOT/pam/gdm-password" <<'EOF'
auth required pam_selinux_permit.so
auth sufficient pam_unix.so
auth required pam_deny.so
EOF
before_sudo=$(cksum "$ROOT/pam/sudo")
before_gdm=$(cksum "$ROOT/pam/gdm-password")
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install; then
    echo 'post-password auth gate was accepted' >&2; exit 1
fi
[ "$before_sudo" = "$(cksum "$ROOT/pam/sudo")" ]
[ "$before_gdm" = "$(cksum "$ROOT/pam/gdm-password")" ]

# Existing custom PeekIn controls never count as a validated installation.
cat > "$ROOT/pam/sudo" <<'EOF'
auth sufficient pam_peekin.so debug
auth sufficient pam_unix.so
auth required pam_deny.so
EOF
before=$(cksum "$ROOT/pam/sudo")
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install; then
    echo 'custom PeekIn rule was accepted' >&2; exit 1
fi
[ "$before" = "$(cksum "$ROOT/pam/sudo")" ]

valid_gdm() {
    cat > "$ROOT/pam/gdm-password" <<'EOF'
auth required pam_selinux_permit.so
auth sufficient pam_unix.so
auth required pam_deny.so
EOF
}

reject_sudo() {
    printf '%b' "$1" > "$ROOT/pam/sudo"
    valid_gdm
    before_sudo=$(cksum "$ROOT/pam/sudo")
    before_gdm=$(cksum "$ROOT/pam/gdm-password")
    if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install; then
        echo "unsafe layout was accepted: $2" >&2; exit 1
    fi
    [ "$before_sudo" = "$(cksum "$ROOT/pam/sudo")" ]
    [ "$before_gdm" = "$(cksum "$ROOT/pam/gdm-password")" ]
}

reject_sudo '-auth sufficient pam_unix.so\nauth required pam_deny.so\n' '-auth'
reject_sudo 'auth [success=1 default=ignore] pam_env.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n' 'jump control'
reject_sudo 'auth required pam_unix.so\nauth required pam_deny.so\n' 'required pam_unix'
reject_sudo 'auth sufficient pam_unix.so\nauth required pam_deny.so debug\n' 'pam_deny options'
reject_sudo 'auth required pam_env.so # pam_unix.so\nauth required pam_deny.so\n' 'module in comment'
reject_sudo 'auth required pam_env.so pam_unix.so\nauth required pam_deny.so\n' 'module in options'
reject_sudo 'auth sufficient pam_peekin.so\nauth required pam_peekin.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n' 'mixed recognized and custom PeekIn rules'
reject_sudo 'auth required /usr/lib64/security/pam_peekin.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n' 'custom PeekIn module path'

# Special module names in comments/options are data, not module fields.
cat > "$ROOT/pam/sudo" <<'EOF'
auth required pam_echo.so pam_unix.so pam_peekin.so pam_deny.so
auth sufficient pam_unix.so
auth required pam_deny.so
EOF
valid_gdm
PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install
[ "$(grep -c pam_peekin.so "$ROOT/pam/sudo")" = 2 ]

# Both recognized historical forms are relocated to the one canonical position.
cat > "$ROOT/pam/sudo" <<'EOF'
auth sufficient pam_peekin.so
auth required pam_env.so
auth sufficient pam_unix.so try_first_pass
auth requisite pam_deny.so
EOF
cat > "$ROOT/pam/gdm-password" <<'EOF'
auth required pam_selinux_permit.so
auth sufficient pam_unix.so
auth required pam_deny.so
auth sufficient pam_peekin.so
EOF
PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install
[ "$(grep -c '^auth[[:space:]]*\[success=done default=ignore\][[:space:]]*pam_peekin.so$' "$ROOT/pam/sudo")" = 1 ]
! grep -q '^auth sufficient pam_peekin.so$' "$ROOT/pam/sudo"
[ "$(grep -n pam_peekin "$ROOT/pam/sudo" | cut -d: -f1)" -gt "$(grep -n pam_env.so "$ROOT/pam/sudo" | cut -d: -f1)" ]

cat > "$ROOT/pam/sudo" <<'EOF'
auth [success=done default=ignore] pam_peekin.so
auth required pam_env.so
auth sufficient pam_unix.so
auth required pam_deny.so
EOF
valid_gdm
PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install
[ "$(grep -n pam_peekin "$ROOT/pam/sudo" | cut -d: -f1)" -gt "$(grep -n pam_env.so "$ROOT/pam/sudo" | cut -d: -f1)" ]

# Failure replacing the second file restores the first byte-for-byte.
cat > "$ROOT/pam/sudo" <<'EOF'
auth required pam_env.so
auth sufficient pam_unix.so
auth required pam_deny.so
EOF
valid_gdm
before_sudo=$(cksum "$ROOT/pam/sudo")
before_gdm=$(cksum "$ROOT/pam/gdm-password")
if PAM_FAIL_REPLACE=gdm-password PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup install; then
    echo 'injected pair replacement failure succeeded' >&2; exit 1
fi
[ "$before_sudo" = "$(cksum "$ROOT/pam/sudo")" ]
[ "$before_gdm" = "$(cksum "$ROOT/pam/gdm-password")" ]

# A refused PAM layout changes no configuration (the camera is chosen at run
# time), but the face model store permissions are still repaired: a root-only
# store left by an interrupted upgrade must not keep face login broken.
printf '%s\n' 'auth include system-auth' > "$ROOT/pam/sudo"
valid_gdm
cat > "$ROOT/config.ini" <<'EOF'
device_path = none
EOF
before_config=$(cksum "$ROOT/config.ini")
if [ "$(id -u)" = 0 ]; then
    mkdir -m 0700 "$ROOT/models"
    : > "$ROOT/models/root.dat"
    chmod 0600 "$ROOT/models/root.dat"
fi
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/config.ini" SERVICE_GROUP="$(id -gn)" SELINUX=0 ./packaging/system-setup install; then
    echo 'invalid PAM layout was accepted' >&2; exit 1
fi
[ "$before_config" = "$(cksum "$ROOT/config.ini")" ]
if [ "$(id -u)" = 0 ]; then
    [ "$(stat -c %a:%G "$ROOT/models")" = "750:$(id -gn)" ]
    [ "$(stat -c %a:%G "$ROOT/models/root.dat")" = "640:$(id -gn)" ]
    rm -rf "$ROOT/models"
fi

# Upgrade from linux-hello 1.x: settings, face models, IR attestations,
# history and photos are taken over once and never overwritten.
M="$ROOT/migrate"
mkdir -p "$M/old/etc/models" "$M/old/activity" "$M/old/log" "$M/new/etc"
printf '[core]\n# Edit with: sudo linux-hello config\nmovement_challenge = false\n' > "$M/old/etc/config.ini.rpmsave"
echo 'shipped default' > "$M/new/etc/config.ini"
echo '[]' > "$M/old/etc/models/$(id -un).dat"
echo '[]' > "$M/old/etc/ir-profiles.json"
echo '{"time":1}' > "$M/old/activity/$(id -un)"
echo jpeg > "$M/old/log/000000000001-$(id -un).jpg"
migrate() {
    env OLD_ETC="$M/old/etc" OLD_ACTIVITY="$M/old/activity" OLD_SNAPSHOTS="$M/old/log" \
        NEW_ACTIVITY="$M/new/activity" NEW_SNAPSHOTS="$M/new/log" MIGRATION_MARKER="$M/new/marker" \
        PAM_DIR="$ROOT/pam" CONFIG_FILE="$M/new/etc/config.ini" SERVICE_GROUP="$(id -gn)" SELINUX=0 \
        ./packaging/system-setup install > /dev/null 2>&1 || true
}
migrate
grep -q '^movement_challenge = false$' "$M/new/etc/config.ini"
grep -q 'sudo peekin config' "$M/new/etc/config.ini"
grep -q 'shipped default' "$M/new/etc/config.ini.peekin-default"
[ -f "$M/new/etc/models/$(id -un).dat" ] && [ -f "$M/new/etc/ir-profiles.json" ]
[ -f "$M/new/activity/$(id -un)" ] && [ -f "$M/new/log/000000000001-$(id -un).jpg" ]
[ -e "$M/new/marker" ] && [ -f "$M/old/etc/models/$(id -un).dat" ]
echo 'edited after the upgrade' > "$M/new/etc/config.ini"
migrate
grep -q 'edited after the upgrade' "$M/new/etc/config.ini"

# Uninstall must refuse unknown custom rules instead of removing their module.
cat > "$ROOT/pam/sudo" <<'EOF'
auth required pam_peekin.so custom_option
EOF
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup remove; then
    echo 'custom PAM rule survived uninstall without an error' >&2; exit 1
fi
grep -q 'pam_peekin.so custom_option' "$ROOT/pam/sudo"
printf '%s\n' 'auth include system-auth' > "$ROOT/pam/sudo"
printf '%s\n' 'auth required pam_peekin.so' > "$ROOT/pam/system-auth"
if PAM_DIR="$ROOT/pam" CONFIG_FILE="$ROOT/missing" SELINUX=0 ./packaging/system-setup remove; then
    echo 'shared authselect rule survived uninstall without an error' >&2; exit 1
fi
grep -q 'pam_peekin.so' "$ROOT/pam/system-auth"
echo SYSTEM_SETUP_OK
