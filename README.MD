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

Milestone 0 (build resurrection) is complete: the 2018 codebase builds on a modern
toolchain. It is not yet a recommended daily driver. See MILESTONES below.

| | |
|---|---|
| Build | Gradle 8.13, AGP 8, JDK 17 toolchain, NDK 28.2 |
| SDK | compileSdk 35, targetSdk 28, minSdk 24 |
| ABIs | armeabi-v7a, arm64-v8a, x86, x86_64 |

`targetSdk` is deliberately held at 28 until the scoped-storage milestone; do not
raise it casually, it will break all file access at once.

### Container support

Measured from `crypto/engines/` and `crypto/kdf/`, not from upstream's marketing:

| | Supported | Absent (present in VeraCrypt 1.26) |
|---|---|---|
| Ciphers | AES-XTS, Serpent-XTS, Twofish-XTS | Camellia, Kuznyechik, all five cascades |
| Hashes | SHA-512, Whirlpool, RIPEMD-160, SHA-1 | SHA-256, BLAKE2s-256, Streebog |

VeraCrypt's defaults (AES + SHA-512) work. A container created with SHA-256 or any
cascade will not open, and upstream never said so.

Also inherited from upstream: `ExFat.java` declares 23 native methods and calls
`System.loadLibrary`, but no CMake target has ever produced that library. exFAT
support does not work and never did.

## MILESTONES

- **M0 build resurrection** - done
- **M1 test oracle** - desktop VeraCrypt generates fixtures, `cryptsetup tcryptDump`
  verifies them independently, round-trips asserted with `fsck.vfat`
- **M2 scoped storage** - SAF, DocumentsProvider, targetSdk 35
- **M3 unlock the gated features** - hidden volumes, outer-volume protection,
  keyfiles, 128-char passphrases
- **M4 hardening** - key zeroing, no decrypt-to-temp, auto-lock, `allowBackup=false`,
  no persisted trace that a container has a hidden volume
- **M5 release** - F-Droid

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
