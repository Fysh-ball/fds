#!/usr/bin/env bash
# Push the fixture set produced by tools/mkfixtures.sh onto a connected device and run
# the M1 instrumented tests against it.
#
# Instrumented, not JVM unit tests, and that is not a preference: every cipher and hash in
# this app is a JNI call with no Java fallback, so crypto can only be exercised on a real ABI.
#
# Fixtures go into the app's own external files dir. That path needs no storage permission
# and no legacy-storage opt-in, so a failure is always a missing push and never a
# permission puzzle.

set -euo pipefail

# Optional first argument: a test filter, either Class or Class#method. Without it the
# whole class runs. The filter exists so a single arm can be timed or re-run on its own
# without paying for the other four.
FILTER="${1:-}"

FIX="${FIX:-/home/user/work/fds-fixtures}"
PKG="${PKG:-site.fysh.fds}"
DEST="/sdcard/Android/data/$PKG/files/fixtures"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

# Resolve adb from the SAME sdk gradle builds against. local.properties is authoritative
# for this repo; ANDROID_HOME on this box points at a directory that does not exist, and
# picking it would run the tests against a different platform-tools than the build used.
resolve_adb() {
    local cand
    for cand in \
        "${ADB:-}" \
        "$(sed -n 's/^sdk\.dir=//p' "$REPO/local.properties" 2>/dev/null)/platform-tools/adb" \
        "${ANDROID_HOME:-}/platform-tools/adb" \
        "${ANDROID_SDK_ROOT:-}/platform-tools/adb" \
        "$HOME/Android/Sdk/platform-tools/adb" \
        "$(command -v adb 2>/dev/null || true)"
    do
        [ -n "$cand" ] && [ -x "$cand" ] && { printf '%s' "$cand"; return 0; }
    done
    return 1
}
ADB="$(resolve_adb)" || { echo "FAIL: no usable adb found (tried \$ADB, local.properties sdk.dir, \$ANDROID_HOME, \$ANDROID_SDK_ROOT, ~/Android/Sdk, PATH)" >&2; exit 1; }
echo "adb: $ADB"
[ -d "$FIX" ] || { echo "FAIL: fixture dir $FIX does not exist. Run tools/mkfixtures.sh." >&2; exit 1; }
for m in manifest.tsv payload-manifest.tsv hidden-manifest.tsv; do
    [ -f "$FIX/$m" ] || { echo "FAIL: $FIX/$m missing. Run tools/mkfixtures.sh and tools/mkhiddenfixture.sh." >&2; exit 1; }
done

devices=$("$ADB" devices | awk 'NR>1 && $2=="device" {print $1}')
if [ -z "$devices" ]; then
    echo "FAIL: no device in state 'device'." >&2
    "$ADB" devices >&2
    exit 1
fi
echo "device(s): $(echo "$devices" | tr '\n' ' ')"

# The app must be installed before its external files dir exists, and the fixtures live
# inside that dir. AGP uninstalls both APKs when connectedAndroidTest finishes, and the
# uninstall takes /sdcard/Android/data/<pkg> with it, so every run would otherwise start
# by deleting the fixtures it is about to need. leaveApksInstalledAfterRun keeps them.
LEAVE=-Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true
echo "== installing =="
(cd "$REPO" && ./gradlew --console=plain $LEAVE :app:installDebug :app:installDebugAndroidTest)

echo "== pushing fixtures =="
"$ADB" shell mkdir -p "$DEST"
# Restore the setgid bit before pushing anything. Emulated storage is FUSE, and it derives a
# new file's gid from the parent directory; adb push then fchown()s the file it just wrote to
# the owner it expects. On a setgid directory that fchown is a no-op and succeeds. On a
# directory whose setgid bit has been cleared the requested gid differs from the one FUSE
# imposed, FUSE refuses the chown, and adb reports
#   remote fchown failed: Operation not permitted
# and DISCARDS the file it had already transferred, so the push both fails and deletes.
# A plain `chmod 777` on this directory clears setgid and is therefore enough to break every
# later push; `chmod a+rX` below does not, which is why the two are not interchangeable.
"$ADB" shell "chmod g+s $DEST"
# Push the manifests LAST. A push interrupted halfway then leaves the manifest absent, so
# the test fails with "manifest missing" instead of silently measuring a partial set.
for f in "$FIX"/*.hc; do
    [ -e "$f" ] || { echo "FAIL: no .hc containers in $FIX" >&2; exit 1; }
    "$ADB" push -q "$f" "$DEST/" >/dev/null
done
for m in manifest.tsv payload-manifest.tsv hidden-manifest.tsv; do
    [ -f "$FIX/$m" ] || { echo "FAIL: $FIX/$m missing. Run tools/mkfixtures.sh and tools/mkhiddenfixture.sh." >&2; exit 1; }
    "$ADB" push -q "$FIX/$m" "$DEST/" >/dev/null
done

# adb creates this directory as uid shell, mode 0770 shell:ext_data_rw. The app owns
# everything above it but is not shell, so opendir() on its OWN fixture directory fails
# and File.list() returns null: "exists=true, canRead()=false". That reads on the Java
# side as an empty or absent directory, which is why this is a chmod and not a comment.
"$ADB" shell "chmod -R a+rX $DEST"

# Enumerate, never head/tail: the question here is "did everything arrive", and truncated
# output would read as absence.
want=$(find "$FIX" -maxdepth 1 -name '*.hc' | wc -l)
got=$("$ADB" shell "ls -1 $DEST/*.hc 2>/dev/null | wc -l" | tr -d '\r')
echo "containers: host=$want device=$got"
[ "$want" -eq "$got" ] || { echo "FAIL: push incomplete ($want != $got)" >&2; exit 1; }

# The manifests are what the tests read first, so verify them by name rather than trusting
# the container count to stand in for them.
for m in manifest.tsv payload-manifest.tsv hidden-manifest.tsv; do
    "$ADB" shell "test -r $DEST/$m" \
        || { echo "FAIL: $m is missing or unreadable at $DEST" >&2; exit 1; }
done
echo "manifests: present and readable"

echo "== running instrumented tests =="
ARGS=()
if [ -n "$FILTER" ]; then
    ARGS+=("-Pandroid.testInstrumentationRunnerArguments.class=$FILTER")
    echo "filter: $FILTER"
else
    # The full negative matrix is 41 containers that each pay the whole hash sweep against
    # both the normal and the hidden header, which is hours. It is @LargeTest and excluded
    # here rather than deleted, and the exclusion is announced so that a green default run
    # is never mistaken for a run of everything. Naming a class explicitly drops it:
    #   tools/run-fixture-tests.sh com.sovworks.eds.fdstest.UnsupportedMatrixTest
    ARGS+=("-Pandroid.testInstrumentationRunnerArguments.notAnnotation=androidx.test.filters.LargeTest")
    echo "excluded: @LargeTest (UnsupportedMatrixTest). Run it by name to include it."
fi
(cd "$REPO" && ./gradlew --console=plain $LEAVE "${ARGS[@]+"${ARGS[@]}"}" :app:connectedDebugAndroidTest)
