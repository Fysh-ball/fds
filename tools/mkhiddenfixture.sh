#!/usr/bin/env bash
# Build one VeraCrypt container that has BOTH an outer and a hidden volume, so the fork's
# hidden-volume support is checked against a real VeraCrypt rather than against itself.
#
# The two volumes get DIFFERENT payloads on purpose. A layout bug that reads the outer header
# when asked for the hidden one, or the reverse, still opens something and still returns a
# valid FAT filesystem: the only thing that catches it is the contents not matching. Equal
# payloads would have made that bug invisible.
#
# Follows the procedure in `veracrypt --text --help`: outer with no filesystem, hidden inside
# it, then mount the outer WITH hidden-volume protection to create and fill its filesystem.

set -euo pipefail

FIX="${1:-/home/user/work/fds-fixtures}"
OUTER_PW='fds-outer-passphrase-do-not-reuse'
HIDDEN_PW='fds-hidden-passphrase-do-not-reuse'
NAME=hidden_AES_SHA_512
CONTAINER="$FIX/$NAME.hc"
MNT="$(mktemp -d)"
MOUNTED=""
MOUNTED_FS=""

cleanup() {
    local rc=$?
    if [ -n "$MOUNTED_FS" ]; then
        sudo -n umount "$MOUNTED_FS" >/dev/null 2>&1 || true
    fi
    if [ -n "$MOUNTED" ]; then
        sudo -n veracrypt --text --non-interactive --dismount "$MOUNTED" >/dev/null 2>&1 || true
    fi
    rmdir "$MNT" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT

vc() { veracrypt --text --non-interactive --random-source=/dev/urandom "$@"; }

mkdir -p "$FIX"
rm -f "$CONTAINER"

echo "1/5 outer volume, no filesystem"
vc --create "$CONTAINER" --size 20M --volume-type=normal --filesystem=none \
   --encryption=AES --hash=SHA-512 --password="$OUTER_PW" --pim=0 --keyfiles=

echo "2/5 hidden volume inside it"
vc --create "$CONTAINER" --size 8M --volume-type=hidden --filesystem=FAT \
   --encryption=AES --hash=SHA-512 --password="$HIDDEN_PW" --pim=0 --keyfiles=

echo "3/5 map the outer volume with hidden-volume protection"
# --filesystem=none maps the volume to a loop device without mounting anything, which is
# required here because step 1 created it with no filesystem. It takes NO mount point: given
# one, veracrypt reads the pair as two commands and refuses with "Only a single command can
# be specified at a time", which names neither of the two options involved.
sudo -n veracrypt --text --non-interactive --mount "$CONTAINER" --filesystem=none \
     --password="$OUTER_PW" --pim=0 --keyfiles= \
     --protect-hidden=yes --protection-password="$HIDDEN_PW" --protection-pim=0 \
     --protection-keyfiles=
MOUNTED="$CONTAINER"

# --list, not --list --volume-properties: those are two commands and veracrypt refuses both.
DEV=$(sudo -n veracrypt --text --non-interactive --list | awk -v c="$CONTAINER" '$2==c {print $3}')
[ -n "$DEV" ] || { echo "FAIL: could not read the outer volume's virtual device" >&2; exit 1; }
echo "     virtual device: $DEV"

# Protection has to be ON for the whole outer write, or the outer filesystem overwrites the
# hidden volume and the fixture silently becomes a normal container with a corrupt second
# header. Assert it rather than assume the flag took.
sudo -n veracrypt --text --non-interactive --volume-properties \
    | grep -q '^Hidden Volume Protected: Yes' \
    || { echo "FAIL: the outer volume mounted WITHOUT hidden-volume protection" >&2; exit 1; }

echo "4/5 filesystem on the outer volume, then fill both payloads"
sudo -n mkfs.vfat -F 16 "$DEV" >/dev/null
sudo -n mount "$DEV" "$MNT"
MOUNTED_FS="$MNT"
printf 'outer-volume-decoy\n' | sudo -n tee "$MNT/decoy.txt" >/dev/null
sudo -n sh -c "head -c 65536 /dev/zero | tr '\\0' 'O' > '$MNT/outer.bin'"
sync
sudo -n umount "$MNT"
MOUNTED_FS=""

sudo -n veracrypt --text --non-interactive --dismount "$CONTAINER" >/dev/null
MOUNTED=""

echo "5/5 fill the hidden volume"
sudo -n veracrypt --text --non-interactive --mount "$CONTAINER" "$MNT" \
     --password="$HIDDEN_PW" --pim=0 --keyfiles= --protect-hidden=no
MOUNTED="$CONTAINER"
printf 'hidden-volume-real\n' | sudo -n tee "$MNT/secret.txt" >/dev/null
sudo -n sh -c "head -c 65536 /dev/zero | tr '\\0' 'H' > '$MNT/hidden.bin'"
sync
sudo -n veracrypt --text --non-interactive --dismount "$CONTAINER" >/dev/null
MOUNTED=""

# The two manifests the test reads. Hashes are taken from the host side, before anything
# entered a container, so nothing here is checked against our own writer.
outer_decoy=$(printf 'outer-volume-decoy\n' | sha256sum | cut -d' ' -f1)
outer_bin=$(head -c 65536 /dev/zero | tr '\0' 'O' | sha256sum | cut -d' ' -f1)
hidden_secret=$(printf 'hidden-volume-real\n' | sha256sum | cut -d' ' -f1)
hidden_bin=$(head -c 65536 /dev/zero | tr '\0' 'H' | sha256sum | cut -d' ' -f1)

{
    printf 'volume\tpassphrase\tpath\tsha256\n'
    printf 'outer\t%s\tdecoy.txt\t%s\n'  "$OUTER_PW"  "$outer_decoy"
    printf 'outer\t%s\touter.bin\t%s\n'  "$OUTER_PW"  "$outer_bin"
    printf 'hidden\t%s\tsecret.txt\t%s\n' "$HIDDEN_PW" "$hidden_secret"
    printf 'hidden\t%s\thidden.bin\t%s\n' "$HIDDEN_PW" "$hidden_bin"
} > "$FIX/hidden-manifest.tsv"

# A run that produced nothing must not exit 0.
[ -s "$CONTAINER" ] || { echo "FAIL: $CONTAINER is missing or empty" >&2; exit 1; }
rows=$(( $(wc -l < "$FIX/hidden-manifest.tsv") - 1 ))
[ "$rows" -eq 4 ] || { echo "FAIL: hidden-manifest.tsv has $rows rows, expected 4" >&2; exit 1; }
# Read both volumes back with a real veracrypt before declaring the fixture good. Filling the
# hidden volume is the step that can destroy the outer one, and the reverse, so a fixture that
# only ever gets checked by the code under test would hide it.
verify_volume() {
    local pw="$1" want_type="$2" m; m="$(mktemp -d)"
    sudo -n veracrypt --text --non-interactive --mount "$CONTAINER" "$m" \
        --password="$pw" --pim=0 --keyfiles= --protect-hidden=no >/dev/null 2>&1 \
        || { echo "FAIL: the $want_type volume does not mount" >&2; rmdir "$m"; return 1; }
    local listing; listing=$(sudo -n ls -1 "$m" | sort | tr '\n' ' ')
    sudo -n veracrypt --text --non-interactive --dismount "$CONTAINER" >/dev/null 2>&1
    rmdir "$m"
    echo "  $want_type volume holds: $listing"
    [ -n "$listing" ] || { echo "FAIL: the $want_type volume is empty" >&2; return 1; }
}
verify_volume "$OUTER_PW"  outer
verify_volume "$HIDDEN_PW" hidden

echo "OK: $CONTAINER ($(stat -c%s "$CONTAINER") bytes), $rows manifest rows"
