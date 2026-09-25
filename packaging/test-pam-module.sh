#!/bin/sh
# End-to-end test of the real pam_peekin.so through libpam, with a stub
# recognition worker instead of a camera:
#   sudo PEEKIN_E2E=1 sh packaging/test-pam-module.sh [target-dir]
#
# It creates the dedicated "peekin" system account if it is missing, so
# run it only in a disposable container/VM (it refuses without
# PEEKIN_E2E=1). No live PAM file is read or changed: the PAM stack lives
# in a private directory used through pam_start_confdir().
set -eu

[ "${PEEKIN_E2E:-0}" = 1 ] || { echo "skipped: set PEEKIN_E2E=1 in a disposable environment"; exit 0; }
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }

ROOT_DIR=$(cd "$(dirname "$0")/.." && pwd)
TARGET=${1:-${CARGO_TARGET_DIR:-$ROOT_DIR/target}/debug}
MODULE=$TARGET/libpam_peekin.so
HARNESS=$TARGET/examples/pam-harness
[ -f "$MODULE" ] && [ -x "$HARNESS" ] || {
    echo "build first: cargo build -p peekin-pam --lib --examples" >&2
    exit 1
}

getent group video >/dev/null || groupadd -r video
getent passwd peekin >/dev/null ||
    useradd -r -U -G video -s /usr/sbin/nologin -d /nonexistent peekin
GID=$(getent group peekin | cut -d: -f3)
USER_UNDER_TEST=peekin-e2e
getent passwd "$USER_UNDER_TEST" >/dev/null || useradd -M -s /usr/sbin/nologin "$USER_UNDER_TEST"

W=$(mktemp -d /tmp/peekin-e2e.XXXXXX)
trap 'rm -rf "$W"' EXIT
chmod 0755 "$W"
mkdir -p "$W/etc/models" "$W/data" "$W/pam" "$W/out" "$W/activity"
chmod 0711 "$W/activity"
chmod 1777 "$W/out"
touch "$W/camera"   # stands in for the configured capture node
sed "s|^device_path = none|device_path = $W/camera|" "$ROOT_DIR/data/config.ini" > "$W/etc/config.ini"
printf '[]\n' > "$W/etc/models/$USER_UNDER_TEST.dat"
chown root:"$GID" "$W/etc/models" "$W/etc/models/$USER_UNDER_TEST.dat"
chmod 0750 "$W/etc/models"
chmod 0640 "$W/etc/models/$USER_UNDER_TEST.dat"

# Stub worker: records its argv and identity, exits with the requested code.
cat > "$W/compare" <<EOF
#!/bin/sh
echo "\$*" > $W/out/args
id -un > $W/out/who
echo "OCL=\$OPENCV_OPENCL_RUNTIME BLAS=\$OPENBLAS_NUM_THREADS" > $W/out/env
code=\$(cat $W/exit-code)
[ "\$code" = 0 ] && echo "matched-model 1"
if [ -e $W/low-light ]; then
    echo low-light
    sleep 0.5
    cat $W/backlight/panel/brightness > $W/out/brightness
fi
exit \$(cat $W/exit-code)
EOF
chmod 0755 "$W/compare"
cat > "$W/pam/sudo" <<EOF
auth [success=done default=ignore] $MODULE config_dir=$W/etc data_dir=$W/data compare=$W/compare state_dir=$W/state backlight_dir=$W/backlight activity_dir=$W/activity
auth required pam_deny.so
EOF
# The same stack with a password that always succeeds (pam_permit), to check
# that a password login clears the failed-attempt counter via pam_setcred.
sed 's/pam_deny.so/pam_permit.so/' "$W/pam/sudo" > "$W/pam-permit"

fail() { echo "FAIL: $*" >&2; echo "--- output"; cat "$W/log" >&2; exit 1; }
run() { # $1 = worker exit code; prints the harness conversation to $W/log
    echo "$1" > "$W/exit-code"
    rm -f "$W/out/args"
    "$HARNESS" "$W/pam" sudo "$USER_UNDER_TEST" > "$W/log" 2>&1 && return 0 || return 1
}

# 1. Movement challenge on (default): randomized sequence announced and passed.
run 0 || fail "matching worker must authenticate"
grep -q "turn your head" "$W/log" || fail "challenge prompt missing"
grep -Eq -- "--challenge (left|right),(left|right),(left|right) -- $USER_UNDER_TEST" "$W/out/args" || fail "challenge not passed to worker"
[ "$(cat "$W/out/who")" = peekin ] || fail "worker must run as the service account"
grep -q "OCL=disabled BLAS=1" "$W/out/env" || fail "worker environment not applied"
# The attempt is in the user's history, with the matching model, readable by
# that user (ACL) but root-owned.
H="$W/activity/$USER_UNDER_TEST"
grep -q '"outcome":"success","model":1' "$H" || fail "success not recorded in the history"
grep -q '"service":"sudo"' "$H" || fail "service not recorded"
[ "$(stat -c %u:%a "$H")" = 0:640 ] || fail "history file must be root-owned with a user ACL ($(stat -c %u:%a "$H"))"
runuser -u "$USER_UNDER_TEST" -- cat "$H" > /dev/null || fail "user cannot read their own history"
runuser -u peekin -- cat "$H" > /dev/null 2>&1 && fail "another account can read the history"

# 2. Failures are explained to the user and fall through (PAM_AUTH_ERR -> deny).
run 16 && fail "failed challenge must not authenticate"
grep -q '"outcome":"challenge-failed"' "$H" || fail "failed challenge not recorded"
grep -q "Head movement did not follow the instructions" "$W/log" || fail "challenge failure not explained"
run 14 && fail "camera failure must not authenticate"
grep -q "The camera could not be opened" "$W/log" || fail "camera failure not explained"

# 3. Challenge off. The stand-in camera is no attested infrared camera, so by
# default the head movement is still required; only with that switched off
# too: short prompt and --challenge none.
sed -i 's/^movement_challenge = true/movement_challenge = false/' "$W/etc/config.ini"
run 0 || fail "movement kept on must authenticate on a match"
grep -Eq -- "--challenge (left|right),(left|right),(left|right) -- $USER_UNDER_TEST" "$W/out/args" || fail "head movement must stay on without an infrared camera"
sed -i 's/^require_movement_without_ir = true/require_movement_without_ir = false/' "$W/etc/config.ini"
run 0 || fail "passive mode must authenticate on a match"
grep -q "Face check: look at the camera." "$W/log" || fail "passive prompt missing"
grep -q "turn your head" "$W/log" && fail "passive mode must not ask for head turns"
grep -q -- "--challenge none -- $USER_UNDER_TEST" "$W/out/args" || fail "passive mode not passed to worker"

# 4. Preflight: nothing is announced and the worker never starts when it could not work.
chmod 0700 "$W/etc/models"
run 0 && fail "unreadable model store must not authenticate"
[ -e "$W/out/args" ] && fail "worker started despite an unreadable model store"
grep -q "Face check" "$W/log" && fail "prompt shown although the scan cannot start"
chmod 0750 "$W/etc/models"
# A face model others could change, or one with an ACL, is refused as well.
chmod 0660 "$W/etc/models/$USER_UNDER_TEST.dat"
run 0 && fail "group-writable face model must not authenticate"
[ -e "$W/out/args" ] && fail "worker started despite a group-writable face model"
chmod 0640 "$W/etc/models/$USER_UNDER_TEST.dat"
if command -v setfacl >/dev/null 2>&1 && setfacl -m u:65534:r "$W/etc/models/$USER_UNDER_TEST.dat" 2>/dev/null; then
    run 0 && fail "face model with an ACL must not authenticate"
    [ -e "$W/out/args" ] && fail "worker started despite a face model with an ACL"
    setfacl -b "$W/etc/models/$USER_UNDER_TEST.dat"
fi
rm "$W/camera"
run 0 && fail "missing camera must not authenticate"
[ -e "$W/out/args" ] && fail "worker started without a camera"
touch "$W/camera"

# 5. Nobody in front of the camera: explained, and not a failed attempt.
#    Without the head turns it counts for nothing (the counter is created
#    before each scan and stays empty); after them, on its own streak.
run 17 && fail "no face must not authenticate"
grep -q "No face seen; use your password" "$W/log" || fail "no-face outcome not explained"
[ -s "$W/state/$USER_UNDER_TEST" ] && fail "no face seen without head turns must not count"
sed -i 's/^movement_challenge = false/movement_challenge = true/' "$W/etc/config.ini"
sed -i 's/^require_movement_without_ir = false/require_movement_without_ir = true/' "$W/etc/config.ini"
run 17 && fail "no face must not authenticate"
[ "$(cut -d' ' -f1,3 "$W/state/$USER_UNDER_TEST")" = "0 1" ] || fail "no face after head turns must count on its own streak"

# 6. Five rejected faces pause face login: no prompt, no worker, a message.
sed -i 's/^max_failed_attempts = 5/max_failed_attempts = 3/' "$W/etc/config.ini"
for i in 1 2 3; do run 11 && fail "rejected face must not authenticate"; done
[ "$(cut -d' ' -f1 "$W/state/$USER_UNDER_TEST")" = 3 ] || fail "failures not counted"
run 0 && fail "paused face login must not authenticate"
[ -e "$W/out/args" ] && fail "worker started while face login is paused"
grep -q "Face login paused after too many failed attempts" "$W/log" || fail "pause not explained"
grep -q '"outcome":"paused"' "$H" || fail "pause not recorded in the history"

# 7. A successful password login (pam_setcred) clears the counter.
mkdir -p "$W/pam2" && cp "$W/pam-permit" "$W/pam2/sudo"
echo 0 > "$W/exit-code"
"$HARNESS" "$W/pam2" sudo "$USER_UNDER_TEST" > "$W/log" 2>&1 || fail "password stand-in must succeed"
[ -e "$W/state/$USER_UNDER_TEST" ] && fail "password login must clear the counter"
run 0 || fail "face login must work again after a password login"

# 8. A successful face login also clears the counter.
run 11 || true
run 0 || fail "matching face must authenticate"
[ -e "$W/state/$USER_UNDER_TEST" ] && fail "face success must clear the counter"

# 8b. Ten scans in a row without a face after the head turns were asked for
#     pause face login; a rejected face in between does not end the streak,
#     a password login does.
for i in 1 2 3 4 5 6 7 8 9; do run 17 && fail "no face must not authenticate"; done
run 11 && fail "rejected face must not authenticate"
run 17 && fail "no face must not authenticate"
[ "$(cut -d' ' -f1,3 "$W/state/$USER_UNDER_TEST")" = "1 10" ] || fail "no-face streak not counted ($(cat "$W/state/$USER_UNDER_TEST"))"
run 0 && fail "face login paused after scans without a face must not authenticate"
[ -e "$W/out/args" ] && fail "worker started while paused after scans without a face"
grep -q "Face login paused after too many scans without a face" "$W/log" || fail "no-face pause not explained"
"$HARNESS" "$W/pam2" sudo "$USER_UNDER_TEST" > "$W/log" 2>&1 || fail "password stand-in must succeed"
[ -e "$W/state/$USER_UNDER_TEST" ] && fail "password login must clear the no-face streak"
run 0 || fail "face login must work again after a password login"

# 9. A damaged counter, or a counter directory where no failure could be
#    recorded, turns face login off: no prompt, no worker, an explanation.
#    A password login clears a damaged counter.
printf 'garbage\n' > "$W/state/$USER_UNDER_TEST"
run 0 && fail "damaged counter must not allow face login"
[ -e "$W/out/args" ] && fail "worker started with a damaged counter"
grep -q "turn your head" "$W/log" && fail "prompt shown although the counter is damaged"
grep -q "Face authentication is unavailable" "$W/log" || fail "damaged counter not explained"
"$HARNESS" "$W/pam2" sudo "$USER_UNDER_TEST" > "$W/log" 2>&1 || fail "password stand-in must succeed"
[ -e "$W/state/$USER_UNDER_TEST" ] && fail "password login must clear a damaged counter"
run 0 || fail "face login must work again after a password login"
chmod 0777 "$W/state"
run 0 && fail "a counter directory writable by others must not allow face login"
[ -e "$W/out/args" ] && fail "worker started although no failure could be recorded"
grep -q "Face authentication is unavailable" "$W/log" || fail "unusable counter not explained"
chmod 0700 "$W/state"
run 0 || fail "face login must work again with a sound counter directory"

# 10. [services]: each place follows its switch; the worker never starts
#     where face login is off.
cp "$W/pam/sudo" "$W/pam/login"
sed -i 's/^sudo = true/sudo = false/' "$W/etc/config.ini"
run 0 && fail "sudo must not use face login when switched off"
[ -e "$W/out/args" ] && fail "worker started for a switched-off service"
sed -i 's/^sudo = false/sudo = true/' "$W/etc/config.ini"
echo 0 > "$W/exit-code"; rm -f "$W/out/args"
"$HARNESS" "$W/pam" login "$USER_UNDER_TEST" > "$W/log" 2>&1 && fail "console login is off by default"
[ -e "$W/out/args" ] && fail "worker started for the console while it is off"
sed -i 's/^console = false/console = true/' "$W/etc/config.ini"
"$HARNESS" "$W/pam" login "$USER_UNDER_TEST" > "$W/log" 2>&1 || fail "console login must work when switched on"
sed -i 's/^console = true/console = false/' "$W/etc/config.ini"

# 11. A dark scene: the screen is at full brightness during the scan and
#     back to its level afterwards; nothing changes with the switch off.
mkdir -p "$W/backlight/panel"
echo raw > "$W/backlight/panel/type"
echo 400 > "$W/backlight/panel/max_brightness"
echo 120 > "$W/backlight/panel/brightness"
chmod -R a+rX "$W/backlight"
touch "$W/low-light"
run 0 || fail "a dark scene must still authenticate on a match"
[ "$(cat "$W/out/brightness")" = 400 ] || fail "screen not brightened during the scan"
[ "$(cat "$W/backlight/panel/brightness")" = 120 ] || fail "brightness not restored"
sed -i 's/^brighten_screen = true/brighten_screen = false/' "$W/etc/config.ini"
run 0 || fail "authentication with brighten_screen off"
[ "$(cat "$W/out/brightness")" = 120 ] || fail "screen brightened although switched off"
sed -i 's/^brighten_screen = false/brighten_screen = true/' "$W/etc/config.ini"
rm "$W/low-light"

# 12. A malformed security setting fails closed without prompting.
sed -i 's/^movement_challenge = true/movement_challenge = perhaps/' "$W/etc/config.ini"
run 0 && fail "malformed movement_challenge must fail closed"
[ -e "$W/out/args" ] && fail "worker started with a malformed security setting"

echo "PAM_MODULE_E2E_OK: challenge, passive, failure messages, preflight, model store, lockout, no-face limit, damaged counter, services, screen light, history, fail-closed"
