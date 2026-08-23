# FDS - Fysh Derived Security

Encrypted file containers on Android, with the key derived from **your passphrase**.

A maintained fork of [EDS Lite](https://github.com/sovworks/edslite) (dead since
2020-04-21), unpaywalled and modernised. Reads and writes VeraCrypt, TrueCrypt,
LUKS and EncFS containers without root.

## Why not Samsung Secure Folder

Secure Folder's data key is generated inside and wrapped by Knox Vault. Your PIN
authenticates you to the keystore that releases that key; it is not the input to a
key derivation function. So the container is bound to one device, cannot be opened
from a PC, cannot be backed up as something you can still decrypt, and its strength
rests on Knox rather than on your passphrase.

FDS derives the key from the passphrase, using the container format's own KDF.
Move the file anywhere, open it with any compatible implementation.

## Status

Not a recommended daily driver yet. What is done and measured, as of 2026-08-22:

| | |
|---|---|
| Build | Gradle 8.13, AGP 8, JDK 17 toolchain, NDK 28.2 |
| SDK | compileSdk 35, targetSdk 28, minSdk 24 |
| ABIs | armeabi-v7a, arm64-v8a, x86, x86_64 |
| Test oracle | 51 containers built by desktop VeraCrypt 1.26, opened by an instrumented suite on-device |

`targetSdk` is deliberately held at 28 until the scoped-storage milestone; do not
raise it casually, it will break all file access at once.

### Container support

Measured from the two registries the open path actually consults, not from the
directory listing of `crypto/`: `EncryptionEnginesRegistry` for ciphers, and
`StdLayout.getSupportedHashFuncs()` plus the VeraCrypt override for hashes.

| | Supported | Absent (present in VeraCrypt 1.26) |
|---|---|---|
| Ciphers | AES-XTS, Serpent-XTS, Twofish-XTS | Camellia, Kuznyechik, every cascade |
| Hashes, VeraCrypt | SHA-512, SHA-256, Whirlpool, RIPEMD-160 | BLAKE2s-256, Streebog |
| Hashes, TrueCrypt | SHA-512, Whirlpool, RIPEMD-160 | (TrueCrypt had no others) |

That is 12 of the 60 cipher-hash combinations VeraCrypt 1.26 offers, which
understates real-world coverage: VeraCrypt's own default is AES + SHA-512.

`crypto/kdf/` also contains an HMAC-SHA1 KDF. No volume layout offers it, so a
container made with SHA-1 will not open, and counting it as supported would have
been wrong. An earlier draft of this table did exactly that.

Also inherited from upstream: `ExFat.java` declares 23 native methods and calls
`System.loadLibrary`, but no CMake target in this tree has ever produced that
library. exFAT support does not work and never did. The instrumented suite
asserts the module is absent, so a build that starts producing it turns red here
instead of quietly contradicting this paragraph.

### Unlock cost

Measured on the x86_64 emulator by `KdfTest#reportPerHashKdfCost`, debug build,
native code at `-O2`. These are the numbers for ONE hash attempt at VeraCrypt's
own iteration counts, not for the whole unlock:

| Hash | us/iteration | iterations | one attempt |
|---|---|---|---|
| SHA-512 | 74 | 500000 | 37 s |
| SHA-256 | 111 | 500000 | 55 s |
| Whirlpool | 121 | 500000 | 61 s |
| RIPEMD-160 | 445 | 655331 | 292 s |

An unlock tries the hashes in that order and stops at the one that produces a
header whose CRC checks, so a SHA-512 container costs 37 s and a Whirlpool one
costs 37 + 55 + 61. A container this fork cannot open costs the whole sweep,
twice, because the hidden header is scanned too.

Measured end to end from the app's own log, one wrong passphrase against a 5 MiB
AES/SHA-512 container on the same emulator:

| Pass | Cost |
|---|---|
| LUKS, then TrueCrypt (1000 and 2000 iterations) | about 2 s |
| VeraCrypt, normal header, all four hashes | 31 + 48 + 58 + about 290 s |
| VeraCrypt, hidden header, all four hashes | the same again |
| total before the app can say "wrong passphrase" | about 15 minutes |

That is a usability defect, not just a slow test. The container layer can already
be told which hash and which engine to use (`VolumeLayout.setHashFunc`,
`setEngine`, both called from `EdsContainerBase.tryLayout`), exactly as desktop
VeraCrypt lets you pick the PRF; nothing in the UI ever sets them, so every
unlock and every typo pays the full search. Exposing them is an M3 item.

Two things follow. First, the hash order in `StdLayout` and `VolumeLayout` is a
cost decision and nothing else: a wrong hash cannot pass the header CRC, so
trying the cheap ones first is free. Second, the debug native build passes no
`-O` flag of its own, so clang defaults to `-O0`; `app/CMakeLists.txt` appends
`-O2` to `CMAKE_C_FLAGS_DEBUG` for that reason. Before that, RIPEMD-160 measured
about five minutes per attempt. Any timing taken from a build without it is a
measurement of `-O0`.

A phone is not this emulator and these are not phone numbers. What they are good
for is the shape: the ratios between the hashes, and the fact that an unsupported
container is by far the most expensive thing the app can be asked to do.

### Hidden volumes

Unlocked, and checked against a two-volume container built by desktop VeraCrypt
with deliberately different contents in each volume.

EDS Lite shipped the plumbing and answered "no" in two methods. `HiddenLayout`
and `veracrypt.HiddenVolumeLayout` point the existing layout at the second of the
four 64 KiB header slots; nothing in the crypto path changed, because the header
carries its own data-area offset. A container with no hidden volume holds random
bytes in that slot, which fail the header CRC exactly as a wrong passphrase does,
which is the property the whole feature depends on.

**Writing to the outer volume of a container that has a hidden volume will
destroy the hidden one.** VeraCrypt guards against this with outer-volume
protection, which FDS does not implement yet. Until it does, mount the outer
volume read-only or not at all. Creating hidden volumes is also not implemented:
use desktop VeraCrypt for that.

### Keyfiles

Not implemented, and not merely switched off. The whole tree contains three
references to the feature and none of them is an implementation. See NOTICE.

## MILESTONES

- **M0 build resurrection** - done
- **M1 test oracle** - done. `tools/mkfixtures.sh` builds the 60-cell VeraCrypt
  matrix with a desktop VeraCrypt, `tools/mkhiddenfixture.sh` builds the
  two-volume container, `tools/run-fixture-tests.sh` pushes them and runs the
  instrumented suite. Fixtures are never created by this app, so the fork is
  never checked against its own writer.
- **M2 scoped storage** - SAF, DocumentsProvider, targetSdk 35
- **M3 unlock the gated features** - hidden volumes done, VeraCrypt passphrase
  cap raised from TrueCrypt's 64 to VeraCrypt's 128. Outstanding: outer-volume
  protection, hidden volume creation, keyfiles (has to be written from scratch),
  PIM and hash/cipher selection exposed in the UI
- **M4 hardening** - `allowBackup=false` done, `FLAG_SECURE` now defaults on.
  Outstanding: key zeroing audit, auto-lock, no persisted trace that a container
  has a hidden volume, and an audit of the decrypt-to-temp path. That last one is
  not a stray copy to fix but a feature: `TempFilesMonitor`, `PrepareTempFilesTask`
  and `ClearTempFolderTask` exist so another app can open a file out of a
  container, and the temp folder is `getWorkDir()`, which defaults to the empty
  string. What it resolves to, whether it survives a lock, and whether it is
  overwritten rather than unlinked are three separate questions and none of them
  has been measured yet
- **M5 release** - F-Droid

## Testing

    tools/mkfixtures.sh          # needs desktop veracrypt and passwordless sudo
    tools/mkhiddenfixture.sh
    tools/run-fixture-tests.sh   # optional argument: Class or Class#method

The suite is instrumented rather than JVM unit tests, and that is not a
preference: every cipher and hash here is a JNI call with no Java fallback, so
the crypto can only be exercised on a real ABI.

| Class | What it checks | Oracle |
|---|---|---|
| `ContainerFixtureTest` | supported containers open and round-trip; a sample of the unsupported ones do not; a wrong passphrase does not | desktop VeraCrypt 1.26 |
| `HiddenVolumeTest` | both volumes of a two-volume container open, and their contents differ | desktop VeraCrypt 1.26 |
| `KdfTest` | PBKDF2 against published vectors; the `javax.crypto.Mac` fast path agrees byte for byte with the generic HMAC; per-hash cost | OpenSSL via Python `hashlib` |
| `CipherKatTest` | AES-XTS, RIPEMD-160 and Whirlpool known answers; Serpent and Twofish round-trip and are distinct from AES | OpenSSL |
| `UnsupportedMatrixTest` | the FULL negative matrix, all 41 | desktop VeraCrypt 1.26 |

`UnsupportedMatrixTest` is `@LargeTest` and the runner excludes it unless you
name it, because every fixture in it pays the whole hash sweep twice. The
default run says out loud that it skipped it, and the sampled arm inside
`ContainerFixtureTest` prints the fixtures it did not test. A coverage cut that
leaves no trace reads afterwards as coverage.

Serpent and Twofish have no known-answer test here and that is a real gap, not
an oversight: OpenSSL implements neither, so there is no second implementation
on the build host to disagree with ours. They are covered by the container
fixtures instead, which is a weaker statement about the primitive and a stronger
one about the stack.

## Building

    ./gradlew :app:assembleDebug

Requires JDK 17+ and an Android SDK with NDK 28.2.13676358 and CMake 3.22.1. Put
`sdk.dir=/path/to/Android/Sdk` in `local.properties`.

Release signing reads `fds.release.storeFile` / `storePassword` / `keyAlias` /
`keyPassword` from `local.properties`, which is gitignored. Without them the
release variant builds unsigned. Never put signing credentials in
`gradle.properties`.

## Licence

GPL-3.0. Upstream is GPL-2.0-or-later; see NOTICE for the provenance and for why
this repository is the one Fysh project that is not AGPL-3.0.

VeraCrypt is a trademark of IDRIX; TrueCrypt of the TrueCrypt Foundation. FDS is
compatible with their container formats and affiliated with neither.
