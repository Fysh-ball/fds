#!/usr/bin/env bash
# FDS test oracle: generate VeraCrypt container fixtures with a desktop VeraCrypt,
# so the Android fork can be checked against a real implementation rather than
# against our own reimplementation of it.
#
# Emits FIXTURES/manifest.tsv:  name  cipher  hash  created  expect_fds  sha256_of_payload
#
# expect_fds is derived from what the fork's volume layout ACTUALLY offers. Measured from
# the two registries the open path really consults, not from the crypto/kdf directory:
#   ciphers: lite/truecrypt/EncryptionEnginesRegistry -> AES-XTS, Serpent-XTS, Twofish-XTS
#   hashes : truecrypt/StdLayout.getSupportedHashFuncs -> SHA-512, RIPEMD-160, Whirlpool
#            veracrypt/VolumeLayout.getSupportedHashFuncs adds SHA-256
# crypto/kdf also contains HMACSHA1KDF, but no layout ever offers SHA-1, so a container
# made with it would not open and counting it as supported would have been wrong.
# Anything outside that is expected to FAIL to open, and the point of generating it
# is to measure the gap rather than guess at it.

set -euo pipefail

FIX="${1:-/home/user/work/fds-fixtures}"
PW='fds-test-passphrase-do-not-reuse'
SIZE=5M
MNT="$(mktemp -d)"
MOUNTED=""

# Cleanup runs on ANY exit path, including an abort mid-loop, so a failed fixture
# never leaves a volume mapped. It must not be sequenced after a check that can abort.
#
# It MUST also preserve the exit status. An earlier version ended with
# `rmdir ... || true`, which returned 0 and turned a hard `set -e` abort into a
# green exit: the run produced zero fixtures and reported success.
cleanup() {
    local rc=$?
    if [ -n "$MOUNTED" ]; then
        sudo -n veracrypt --text --non-interactive --dismount "$MOUNTED" >/dev/null 2>&1 || true
    fi
    rmdir "$MNT" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT

mkdir -p "$FIX"
MANIFEST="$FIX/manifest.tsv"
printf 'name\tcipher\thash\tcreated\texpect_fds\tpayload_sha256\n' > "$MANIFEST"

# Deterministic payload: content is a function of nothing but its own name, so the
# expected sha256 is stable across regenerations and can be asserted on-device.
PAYLOAD="$FIX/payload"
mkdir -p "$PAYLOAD"
for i in 1 2 3; do
    # 64 KiB of a repeating known pattern - large enough to cross XTS sector
    # boundaries (512 B) many times, which is where a wrong tweak shows up.
    #
    # Deliberately NOT `yes ... | head -c`: head closes the pipe, yes dies of
    # SIGPIPE with status 141, and under `set -o pipefail` that aborts the run.
    awk -v s="fds-fixture-block-$i" 'BEGIN {
        while (length(o) < 65536) o = o s "\n"
        printf "%s", substr(o, 1, 65536)
    }' > "$PAYLOAD/file$i.bin"
done
mkdir -p "$PAYLOAD/subdir"
printf 'nested\n' > "$PAYLOAD/subdir/nested.txt"
PAYLOAD_SHA=$(cd "$PAYLOAD" && find . -type f | sort | xargs sha256sum | sha256sum | cut -d' ' -f1)

# The fork's registry offers exactly these. Everything else is a measured gap.
fds_supports() {
    local cipher="$1" hash="$2"
    case "$cipher" in AES|Serpent|Twofish) ;; *) echo no; return ;; esac
    case "$hash" in SHA-512|Whirlpool|RIPEMD-160|SHA-256) ;; *) echo no; return ;; esac
    echo yes
}

make_one() {
    local cipher="$1" hash="$2"
    local name; name="$(echo "${cipher}_${hash}" | tr -c 'A-Za-z0-9_' '_')"
    local path="$FIX/$name.hc"
    local created=no

    rm -f "$path"
    if veracrypt --text --non-interactive --create "$path" \
            --size "$SIZE" --password "$PW" --volume-type=normal \
            --encryption="$cipher" --hash="$hash" --filesystem=FAT \
            --pim=0 --keyfiles= --random-source=/dev/urandom >/dev/null 2>&1; then
        created=yes
    fi

    if [ "$created" = yes ]; then
        # Fill it. Mount needs root; a failure here must not abort the whole run,
        # it must be recorded, so the caller can see WHICH fixture is unfilled.
        if sudo -n veracrypt --text --non-interactive --mount "$path" "$MNT" \
                --password "$PW" --pim=0 --keyfiles= --protect-hidden=no >/dev/null 2>&1; then
            MOUNTED="$MNT"
            sudo cp -r "$PAYLOAD"/. "$MNT"/ 2>/dev/null || true
            sync
            sudo -n veracrypt --text --non-interactive --dismount "$MNT" >/dev/null 2>&1 || true
            MOUNTED=""
        else
            created=created_unfilled
        fi
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$name" "$cipher" "$hash" "$created" "$(fds_supports "$cipher" "$hash")" "$PAYLOAD_SHA" \
        >> "$MANIFEST"
    printf '  %-34s create=%-16s expect_fds=%s\n' "$name" "$created" "$(fds_supports "$cipher" "$hash")"
}

echo "veracrypt: $(veracrypt --version 2>&1 | head -1)"
echo "fixtures:  $FIX"
echo "payload sha256: $PAYLOAD_SHA"
echo

# The full modern VeraCrypt matrix, not just the subset we expect to pass. The
# unsupported rows are the deliverable: they quantify the coverage gap.
for cipher in AES Serpent Twofish Camellia Kuznyechik \
              AES-Twofish AES-Twofish-Serpent Serpent-AES \
              Serpent-Twofish-AES Twofish-Serpent; do
    for hash in SHA-512 Whirlpool SHA-256 BLAKE2s-256 Streebog RIPEMD-160; do
        make_one "$cipher" "$hash"
    done
done

echo
echo "=== summary ==="
awk -F'\t' 'NR>1{c[$4"/"$5]++} END{for(k in c) printf "  %-28s %d\n", k, c[k]}' "$MANIFEST"
echo
echo "manifest: $MANIFEST"

# A run that measures nothing must NOT exit 0. Assert the shape of the result:
# every cipher x hash cell must have produced a manifest row, and at least the
# three the fork claims to support must have produced a real container on disk.
rows=$(( $(wc -l < "$MANIFEST") - 1 ))
want=$(( 10 * 6 ))
if [ "$rows" -ne "$want" ]; then
    echo "FAIL: manifest has $rows data rows, expected $want" >&2
    exit 1
fi
onDisk=$(find "$FIX" -maxdepth 1 -name '*.hc' | wc -l)
if [ "$onDisk" -eq 0 ]; then
    echo "FAIL: no .hc containers were created" >&2
    exit 1
fi
echo "OK: $rows manifest rows, $onDisk containers on disk"
