#!/usr/bin/env bash
# FDS test oracle: VeraCrypt containers whose credential includes KEYFILES.
#
# The keyfile algorithm is not something this codebase gets to choose. A container made by
# desktop VeraCrypt with a keyfile either opens here or it does not, and if our pool mixing
# is wrong the symptom is indistinguishable from a wrong passphrase. So the fixture is made
# by a real veracrypt and the keyfiles are shipped beside it.
#
# The keyfiles are DETERMINISTIC, not random. A random keyfile would make the fixture
# unreproducible: regenerating it would produce a container the committed test data no
# longer describes, and the only way to notice would be a failing test that looks like a
# code regression.
#
# Emits, into $FIX:
#   kf1.bin kf2.bin              the keyfiles
#   keyfile_single.hc            passphrase + kf1
#   keyfile_double.hc            passphrase + kf1 + kf2
#   keyfile_only.hc              EMPTY passphrase + kf1, if veracrypt accepts one
#   keyfile-manifest.tsv         name  password  keyfiles

set -euo pipefail

FIX="${FIX:-/home/user/work/fds-fixtures}"
PW='fds-test-passphrase-do-not-reuse'
MNT="$(mktemp -d)"
MOUNTED=""

# Preserves the exit status, so a failure inside the loop cannot exit 0. The earlier fixture
# script shipped with `|| true` here and turned a hard abort into a green run that produced
# nothing.
cleanup() {
    local rc=$?
    if [ -n "$MOUNTED" ]; then
        sudo -n veracrypt --text --non-interactive --dismount "$MOUNTED" >/dev/null 2>&1 || true
    fi
    rmdir "$MNT" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT

# Creation prints a carriage-return progress meter that becomes several thousand lines in a
# captured log and buries every other message. It goes to a file so a real error is still
# recoverable, rather than to /dev/null.
VCLOG="${VCLOG:-$(mktemp)}"
vc() { veracrypt --text --non-interactive --random-source=/dev/urandom "$@" >>"$VCLOG" 2>&1; }

mkdir -p "$FIX"
KF1="$FIX/kf1.bin"
KF2="$FIX/kf2.bin"

# 4096 bytes cycling 0..255, then 1000 bytes of a different cycle. Both cross the 64 byte
# pool boundary many times, so a wraparound bug cannot hide, and neither is a multiple of
# the pool size in a way that would make an off-by-one alignment error invisible.
python3 - "$KF1" "$KF2" <<'PY'
import sys
open(sys.argv[1], 'wb').write(bytes(i % 256 for i in range(4096)))
open(sys.argv[2], 'wb').write(bytes((i * 7 + 13) % 256 for i in range(1000)))
PY
echo "keyfiles: $(stat -c%s "$KF1") and $(stat -c%s "$KF2") bytes"

MANIFEST="$FIX/keyfile-manifest.tsv"
printf 'name\tpassword\tkeyfiles\n' > "$MANIFEST"

make_one() {
    local name="$1" pw="$2" kfs="$3"
    local path="$FIX/$name.hc"
    rm -f "$path"
    echo "creating $name (keyfiles=$kfs)"
    vc --create "$path" --size 2M --volume-type=normal --filesystem=none \
       --encryption=AES --hash=SHA-512 --password="$pw" --pim=0 --keyfiles="$kfs"

    # set -e is DISABLED inside an `if` condition, and make_one is called from one for the
    # optional fixture below. Without this, a failed create falls straight through: the
    # mount-with check fails, the mount-without check also fails, and the "refuses without"
    # branch reports success for a container that does not exist. A missing file must not be
    # able to reach the manifest.
    if [ ! -s "$path" ]; then
        echo "  create produced no container (veracrypt output in $VCLOG)" >&2
        return 1
    fi

    # Prove it opens WITH the keyfiles. A fixture nobody verified is a fixture that can be
    # broken and still ship.
    # --hash is a restriction, not a hint: without it veracrypt tries every supported hash
    # and cipher before deciding, and on the NEGATIVE check below that means grinding the
    # full matrix to reach a foregone conclusion. The fixtures are all created SHA-512, so
    # naming it costs nothing and bounds both checks.
    if ! sudo -n veracrypt --text --non-interactive --mount "$path" --filesystem=none \
         --hash=sha512 --password="$pw" --pim=0 --keyfiles="$kfs" --protect-hidden=no; then
        echo "  created container does not open with its own keyfiles" >&2
        return 1
    fi
    MOUNTED="$path"
    sudo -n veracrypt --text --non-interactive --dismount "$path" >/dev/null
    MOUNTED=""

    # And prove it does NOT open without them. Without this the fixture would pass every
    # test even if the keyfile had been ignored at creation time, which is exactly the bug
    # the fixture exists to catch.
    if sudo -n veracrypt --text --non-interactive --mount "$path" --filesystem=none \
            --hash=sha512 --password="$pw" --pim=0 --keyfiles= --protect-hidden=no >/dev/null 2>&1; then
        sudo -n veracrypt --text --non-interactive --dismount "$path" >/dev/null 2>&1 || true
        echo "BAD: $name opened with no keyfile, so the keyfile did nothing" >&2
        exit 1
    fi
    echo "  ok: opens with keyfiles, refuses without"
    # BASENAMES, not the host paths veracrypt was given. The manifest is read on the device,
    # where the keyfiles sit beside the containers and the host path does not exist. Writing
    # the host path here would produce a manifest that parses cleanly and resolves to
    # nothing, which is the failure that reads as a keyfile with no bytes in it.
    local base
    base=$(echo "$kfs" | tr ',' '\n' | xargs -r -n1 basename | paste -sd,)
    printf '%s\t%s\t%s\n' "$name" "$pw" "$base" >> "$MANIFEST"
}

make_one keyfile_single "$PW" "$KF1"
make_one keyfile_double "$PW" "$KF1,$KF2"

# An empty passphrase with a keyfile is legal in the format: the keyfile IS the credential
# and the derived password is exactly the 64 byte pool. Not every veracrypt build accepts
# one non-interactively, so this fixture is optional and its absence is reported rather
# than assumed.
if make_one keyfile_only "" "$KF1" 2>/dev/null; then
    echo "empty-passphrase fixture created"
else
    echo "NOTE: this veracrypt refused an empty passphrase non-interactively;"
    echo "      keyfile_only.hc not created and the test must skip that arm explicitly"
    rm -f "$FIX/keyfile_only.hc"
fi

echo
echo "manifest:"
cat "$MANIFEST"
