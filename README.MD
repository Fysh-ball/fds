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

Not a recommended daily driver yet. What is done and measured, as of 2026-08-23:

| | |
|---|---|
| Build | Gradle 8.13, AGP 8, JDK 17 toolchain, NDK 28.2 |
| SDK | compileSdk 35, targetSdk 28, minSdk 24 |
| ABIs | armeabi-v7a, arm64-v8a, x86, x86_64 |
| Test oracle | 51 containers built by desktop VeraCrypt 1.26, opened by an instrumented suite on-device |
| End to end | added, unlocked, listed, written to, closed and reopened through the real UI on an x86_64 emulator |

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

| Hash | us/iteration | iterations | one attempt | was |
|---|---|---|---|---|
| SHA-512 | 72 | 500000 | 36 s | 37 s |
| SHA-256 | 64 | 500000 | 32 s | 55 s |
| Whirlpool | 103 | 500000 | 52 s | 61 s |
| RIPEMD-160 | 287 | 655331 | 188 s | 292 s |

An unlock tries the hashes in that order and stops at the one that produces a
header whose CRC checks, so a SHA-512 container costs 36 s and a Whirlpool one
costs 36 + 32 + 52. A container this fork cannot open costs the whole sweep,
twice, because the hidden header is scanned too.

The `was` column is the same test on the same emulator before two changes: the
`engineDigest(byte[],int,int)` override on the JNI RIPEMD-160 and Whirlpool, which
stopped PBKDF2 allocating a throwaway array twice per iteration, and the removal of
the `javax.crypto.Mac` path described below, which is why SHA-256 nearly halved.

Measured end to end from the app's own log, one wrong passphrase against a 5 MiB
AES/SHA-512 container on the same emulator:

| Pass | Cost |
|---|---|
| LUKS, then TrueCrypt (1000 and 2000 iterations) | about 2 s |
| VeraCrypt, normal header, all four hashes | 31 + 48 + 58 + about 290 s |
| VeraCrypt, hidden header, all four hashes | the same again |
| total before the app can say "wrong passphrase" | about 15 minutes |

That end-to-end run was measured before the two KDF changes above and has not been
repeated since, so the 15 minutes is a real stopwatch reading of code that no longer
exists. Derived from the current per-hash table the same sweep is 2 + 2*(36+32+52+188),
about 10 minutes. It is written as derived because it is: nothing has re-measured it.

That is a usability problem, and the fix was discoverability rather than crypto.
The hints already existed and were already wired: container format, hash
algorithm and encryption algorithm are per-container settings (long-press a
container in Manage containers, then Settings), and PIM is offered per-open
behind the gear button in the password dialog as well as persistently. What was
wrong is that they were off the path: three taps deep behind a long-press, unset
by default, and never suggested by the unlock flow, so the default experience was
the full sweep and a wrong passphrase that took minutes to be rejected. An
earlier draft of this section claimed the UI could not set them at all; it can,
and that claim was wrong.

**FDS now records them itself.** The first successful open already knows exactly
which format, cipher and hash worked, so `ContainerBasedLocation` writes those
three down and every later open uses them. The table above collapses to one row:
one derivation instead of a search, for a correct passphrase and a wrong one
alike. Measured as a hash count rather than a stopwatch, by
`OpenHintTest#aHashHintReplacesTheSearchWithOneDerivation`: two hashes tried
unhinted against a SHA-256 container, one hinted.

Two, not four, because that arm pins the format to VeraCrypt. A real unlock does
not: `EdsContainer.SUPPORTED_FORMATS` is TrueCrypt, VeraCrypt, LUKS in that
order, so an unhinted SHA-256 container is measured through the location as
`[SHA-512, whirlpool, ripemd160, SHA256]`. The first three are the TrueCrypt pass
at 1000 iterations and cost about a second between them, which is why they never
appeared on the stopwatch. The first draft of that test asserted two at the
location level and was wrong about the app, not the other way round.

On the wall clock, through the real UI on the same emulator, an AES/SHA-256
container: **80 s the first time, 40 s every time after.** The 80 s is a SHA-512
derivation that cannot match followed by the SHA-256 one that does; the three
cipher attempts per hash cost nothing measurable, because a wrong cipher fails
the header CRC without a KDF. The hinted open logs one `Using SHA256 hash
function` line and one cipher attempt. Those seconds are from the app's own log
under emulator load and do not match the microbenchmark row above to the second;
the hash count is the part being asserted.

Both wall-clock figures predate the two KDF changes and have not been repeated, so
they overstate the current cost: the same two derivations now measure 36 + 32 s
rather than 37 + 55 s in the microbenchmark. They are left as they were read
instead of being scaled, because a number nobody measured should not be written as
if somebody had.

Two things about that are deliberate and neither is an optimisation.

**A hidden open records nothing.** If it did, the recorded hash would be the
hidden volume's, and someone handed the outer passphrase under duress could mount
the outer volume, read its real hash out of its own header, and see that the two
disagree. That difference is proof a hidden volume exists, which is the one thing
the feature exists to deny. `EdsContainerBase.isHiddenVolumeOpened()` is the flag
that stops it, and `OpenHintTest#theHiddenFlagDistinguishesTheTwoVolumes` asserts
it in both directions on the same file. The cost is that a hidden volume keeps
paying the full search.

**An inferred hint can be thrown away; a hint you set cannot.** They are stored
in separate fields for exactly that reason. If the file at that path is replaced
by a different container the inferred hash stops matching, and nothing in
`EdsContainerBase.tryLayout` retries a failed hint on the normal pass, so the
container would be permanently unopenable. An inferred hint that fails is
therefore discarded and the full search is run once. A hint the user typed is
left in force and the open is allowed to fail, because the alternative is the app
deciding it knows the container better than the person who answered.

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

### The unlock that killed the app

Until 2026-08-23 an unhinted VeraCrypt open on the emulator was killed by the Android
low-memory killer before it finished. It presented as flakiness: one test in
`OpenHintTest` "failed" with an empty `<failure>` element and the run ended with
`Process crashed`, while the same test passed on its own and had passed in a full
34-test run. Two things made it look like host pressure rather than a defect, and both
were wrong.

The cause was `javax.crypto.Mac`. It had been put on the PBKDF2 inner loop in M1 as an
optimisation, on the reasoning that one native HMAC call per iteration must beat the
generic implementation's six MessageDigest calls. Conscrypt allocates a fresh native
`HMAC_CTX` inside every `doFinal()`, and PBKDF2 calls `doFinal` once per iteration. The
Java object wrapping that context is a few dozen bytes, so nothing ever provoked a GC
while the native heap filled. At the moment of the kill the process held 1.58 GB RSS
against a 108 MB Dalvik heap, with the whole balance in `[anon:scudo:primary]`, inside
a guest with 1536 MB of RAM:

```
lowmemorykiller: Kill 'site.fysh.fds' (27847), uid 10192, oom_score_adj 0
  to free 1583048kB rss, 1414692kB swap; reason: min watermark is breached
```

`HmacNativeMemoryTest` measures both implementations in the same process, three rounds,
with the order swapped on the middle round so warm-up cannot be mistaken for a property
of the code. Over 200000 iterations, two independent runs:

| | round 0 | round 1 | round 2 |
|---|---|---|---|
| generic HMAC, RSS delta | +4 MB | -124 MB | -61 MB |
| `javax.crypto.Mac`, RSS delta | +120 MB | +109 MB | +140 MB |
| generic HMAC, elapsed | 9169 ms | 7338 ms | 6112 ms |
| `javax.crypto.Mac`, elapsed | 11301 ms | 9452 ms | 8629 ms |

The negative deltas are the collector catching up with the previous round's Mac garbage
during the generic loop. The Mac path grew the process on all six rounds across both
runs and never once shrank it. It was also slower on five of those six rounds; the
exception is the first round of a run, which pays class loading in whichever arm goes
first.

So the optimisation was wrong in both directions, and the fix was to delete it.
`MacHMAC` now lives in the test sources, out of the shipped APK, doing two jobs that are
worth keeping. It is the byte-for-byte oracle `KdfTest` compares the hand-rolled
ipad/opad loop against, since an HMAC wrong by one byte produces a wrong master key and
an unopenable container with nothing reporting an error. And it is the positive control
in `HmacNativeMemoryTest`: an assertion that the production path "does not grow the
native heap" passes just as green when the loop never ran, when `/proc` stops answering,
and when the measurement itself is broken, so the same run has to contain something that
does grow and does get caught.

Peak RSS for the class that was being killed: 1.58 GB before, 286 MB after.

Two things about the diagnosis are worth writing down. A `Runtime.totalMemory()` check
would have reported this leak absent, because none of it was on the Java heap. And the
first two runs were read as host memory pressure, which was a real condition at the time
(15 GB box, 4 GB available, six concurrent sessions) and had nothing to do with it.

### The fast path that aborted the process

`LocalEncryptedFileXTS` is the fast IO path: when the container is a plain local
file and the cipher mode is XTS, reads and writes go through `liblocalxts.so`
instead of the Java stack. Its `initContext` opened the container with

```c
int fd = open(path, readOnly ? O_RDONLY : (O_RDWR | O_CREAT));
```

`O_CREAT` with no mode argument. On any bionic built with `_FORTIFY_SOURCE`,
which is every current Android, `__open_2` does not return an error for that: it
calls `__fortify_fatal` and the process takes `SIGABRT`.

```
Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 13921 (roidJUnitRunner), pid 13902 (site.fysh.fds)
Abort message: 'FORTIFY: open: called with O_CREAT/O_TMPFILE but no mode'
  #03 pc 0000000000000d7e  liblocalxts.so (Java_com_sovworks_eds_crypto_LocalEncryptedFileXTS_initContext+78)
```

So every read-write open of a local container through the fast path killed the
app outright. It survived because the read-only branch is fine and nothing in the
existing suite opened a local container for writing; it surfaced the first time
`OuterVolumeProtectionTest` did, as an empty `<failure>` element and
`Process crashed`, which is the same shape the low-memory kill above wore.

Adding a mode would have been the wrong fix. `O_CREAT` itself does not belong
here: this call opens an existing container in order to decrypt it, and creating
an empty file when the path is missing produces a zero-length container whose
header cannot be read, turning "that file is gone" into "your container is
corrupt". The flag is gone. The same edit released the `GetStringUTFChars` copy
of the path on the success path, which every early return already released and
which therefore leaked on every successful open.

### The reveal button that erased the passphrase

`EditSB` is the password field. It holds its characters in an
`EditableSecureBuffer` rather than an ordinary `Editable` so the plaintext can be
wiped, and its `setText` clears that buffer before writing the new text, which is
the entire point of the class.

What it did not account for is the case where the incoming text IS the buffer.
`TextView.setTransformationMethod` re-sets the view's own text, and
`setInputType` routes through it whenever the masking changes, so pressing the
reveal button reached `setText(mText)` with `mText` being that very `Editable`.
It was cleared, and the now-empty buffer was then copied back over itself.

Pressing the reveal button erased the passphrase you pressed it to look at. No
message, no log line, nothing in the exception path: the field simply appeared
blank, and the obvious reading is that you had mistyped it. It is upstream
behaviour on the ordinary passphrase field, so it predates this fork.

The fix is an identity check. Every other caller passes a different
`CharSequence` and still gets the buffer wiped first:

```java
if(et != null && et != text)
    et.clear();
```

It was found by refusing to settle an argument by reasoning. The reveal button
had just been extended to unmask the protection passphrase as well, and whether
`setInputType` could reach `setText` on these fields was a question about
`TextView` internals that could be answered either way from the source. Typing
into both fields, toggling twice and reading them back answered it in one run:
`expected.length=12 actual.length=0`.

### Hidden volumes

Unlocked, and checked against a two-volume container built by desktop VeraCrypt
with deliberately different contents in each volume.

EDS Lite shipped the plumbing and answered "no" in two methods. `HiddenLayout`
and `veracrypt.HiddenVolumeLayout` point the existing layout at the second of the
four 64 KiB header slots; nothing in the crypto path changed, because the header
carries its own data-area offset. A container with no hidden volume holds random
bytes in that slot, which fail the header CRC exactly as a wrong passphrase does,
which is the property the whole feature depends on.

### Outer-volume protection

Writing to the outer volume of a container that has a hidden volume destroys the
hidden one. That is not a corner case: the outer filesystem cannot see the hidden
volume by construction, so its allocator writes straight through it the first
time you copy a file in. FDS implements VeraCrypt's answer to this, and the
passphrase field on the unlock dialog is where you turn it on.

Give the hidden volume's passphrase in the second field and the outer volume
mounts read-write with the hidden volume's extent fenced off. Three choices in it
are worth stating, because each one is a place the feature could leak:

- **Reads are never refused.** A refused read would be a distinguisher: a region
  the outer filesystem believes is free would behave differently from the rest of
  the free space, which is exactly the observation the hidden volume exists to
  deny.
- **A refusal latches.** Once one write has been turned away the whole outer
  volume goes read-only for that session. A filesystem that has had a write
  refused mid-operation no longer agrees with its own metadata, and letting the
  next write through would corrupt it for real.
- **A wrong protection passphrase refuses the mount** rather than mounting
  unprotected. "The passphrase is wrong" and "this container has no hidden
  volume" are indistinguishable by design, and neither is safe to write to.

The protection passphrase is asked for every time and stored nowhere, not even in
a saved location. A persisted "this container has a hidden volume" flag would
itself be the proof, readable by whoever is holding the phone. For the same
reason the field is offered on every container whose format supports hidden
volumes, whether or not one is there.

It is offered only where it can mean something: on the open path, never while
creating a container, and only for formats that have hidden volumes at all. LUKS
does not, and asking for a second passphrase there would invite the user to type
one and then refuse the mount, which reads as the app being broken. Gating on the
format leaks nothing, because which formats support hidden volumes is public.

The reveal button unmasks both passphrases together. It did not at first, and the
gap mattered more than it looks: the reason to reveal a passphrase is to check a
long one for a typo, and a typo in the protection passphrase does not announce
itself as one. It refuses the mount with the same message a container holding no
hidden volume gives, which is deliberate, and is exactly why looking at what was
typed is the only way to tell them apart.

Known gap: a location with a saved password skips the unlock dialog, so there is
currently no way to enter a protection passphrase for one.

Creating hidden volumes is still not implemented: use desktop VeraCrypt for that.

### Keyfiles

Not implemented, and not merely switched off. The whole tree contains three
references to the feature and none of them is an implementation. See NOTICE.

### Branding and the About dialog

The app called itself "EDS Lite" everywhere: one string drives the launcher label,
the task title and the About dialog, and it had not been touched. It now says FDS,
along with the eight other user-visible strings that named the old program. The two
that still say "EDS Lite" are version-history entries about releases sovworks made,
and rewriting those would put words in upstream's mouth.

Three things in the About dialog were pointed at a vendor that stopped shipping in
2020 and are gone or repointed:

| Was | Now |
|---|---|
| "Make a donation" -> sovworks.com | removed |
| "Check the full version" -> the paid EDS on Google Play | removed |
| "Check the source code" -> sovworks/edslite | this repository |
| Support mail -> eds@sovworks.com | Admin@fysh.site |

A fork whose premise is that those features should not have been paywalled has no
business shipping a button that sells them. Upstream's repository is still recorded,
as `GlobalConfig.UPSTREAM_SOURCE_URL` and in NOTICE, because GPL attribution needs
somewhere to point; it is provenance, not this app's home.

### Automatic locking

Upstream had none. The only thing that ever closed a container by itself was a
per-container inactivity timer whose default is `-1`, so out of the box nothing
closed a container except the user, and a container left mounted stayed mounted
across a locked screen.

Two locks, both defaulting **on**, both switchable in Settings:

| Setting | Trigger | Why |
|---|---|---|
| Close containers when the screen turns off | `ACTION_SCREEN_OFF` | the threat model starts with a device that left its owner's hands, and a mounted container is readable by whoever picks it up |
| Close containers when the app is swiped away | `Service.onTaskRemoved` | removing the app from recents leaves the background service running, so without this the container outlives the visible app |

`ACTION_SCREEN_OFF` cannot be declared in the manifest, so the receiver is
registered by `LocationsServiceBase` at runtime and unregistered in `onDestroy`.
The close is forced, so unsaved data can be lost: that trade is stated in the
setting's own description rather than buried here.

**A lock also forgets the keys the containers did not hold.** Closing every
location wipes each container's passphrase, because `Location.close()` already
does that. Two pieces of key material outlive every location, though: the master
password the user typed to unlock protected settings, and the 32 byte settings
protection key derived from it. Before this both sat in process memory behind a
locked screen, so the lock closed the containers and left the password that
guards the saved container passwords sitting next to them. Both lock paths now
clear them.

The obvious way to write that is wrong, and the test says so rather than the
comment. `SecureBuffer.closeAll()` erases every registered buffer and looks like
exactly the right call at a lock point. It has no callers here and still does not
after this change, for two reasons. It cannot reach the field that caches the
settings key, so `getSettingsProtectionKey` would go on memoising a dead
buffer, the next protected read would throw `key is closed`, and the app would
report a wrong settings password to a user who never set one. And it is a
process-wide sweep with no notion of what is in use: one of the seven
`SecureBuffer` fields in this tree is held for the whole of a container
creation, and a screen timing out during a several-hundred-thousand-iteration
KDF is not a hypothetical. The lock clears the two holders through their own
methods, which erase the buffer *and* null the field.

Only re-derivation can fail, and only for someone who set a master password:
with none set the key comes back from the device-local automatic password with
nothing to type. For someone who did set one, being asked again after a lock is
the feature.

**Writes inside a mounted container are buffered until close.** A crash, a kill,
or a battery pull loses them. That is inherited behaviour, not something these
locks introduced, but the locks make it reachable more often, and it is not fixed
yet.

### Temp files and wiping

Opening a file from a container with another app decrypts it to a temp file,
which `WipeFilesTask` is supposed to erase. Two defects were found in that path
and neither was visible from the call site:

- It seeded `java.util.Random` from the clock. The bytes that overwrote plaintext
  were reconstructible from the seed, so the overwrite was a pattern, not noise.
  Now `SecureRandom`, which costs nothing measurable at 4 KiB a block.
- It opened the file through `getOutputStream()`, which **truncates to zero** and
  then writes the replacement bytes. A filesystem is free to place the new extent
  anywhere, so the blocks holding the plaintext were released unwritten. It also
  always wrote whole 4 KiB blocks, so a 10000-byte file came back 12288 bytes
  long. Now opened `ReadWrite` through `RandomAccessIO`, never writing past the
  original length.

Still best effort, and this is not a guarantee on flash: wear levelling can
retire the original block instead of rewriting it, and no userspace overwrite can
reach it. The real defence is that these files should not hold plaintext for
long.

The overwrite is split out of `wipeFileRnd` as `overwriteFileRnd` so that it can
be tested at all. A wipe destroys its own evidence by design, so a test of the
combined call can only observe that the file is gone, which is equally true of a
wipe that wrote nothing.

Mirror deletion in `LocationsServiceBase.deleteMirror()` now goes through the
wipe instead of unlinking.

## MILESTONES

- **M0 build resurrection** - done
- **M1 test oracle** - done. `tools/mkfixtures.sh` builds the 60-cell VeraCrypt
  matrix with a desktop VeraCrypt, `tools/mkhiddenfixture.sh` builds the
  two-volume container, `tools/run-fixture-tests.sh` pushes them and runs the
  instrumented suite. Fixtures are never created by this app, so the fork is
  never checked against its own writer.
- **M2 scoped storage** - SAF, DocumentsProvider, targetSdk 35. Raising
  `targetSdk` past 33 also makes the `RECEIVER_EXPORTED` / `RECEIVER_NOT_EXPORTED`
  flag mandatory on every runtime `registerReceiver`: there are eighteen call
  sites across `LocationsServiceBase`, `LocationsManagerBase`, `FileManagerActivityBase`
  and `LocationListBaseFragment`, and an unflagged one throws on first start on
  Android 14 rather than at build time
- **M3 unlock the gated features** - hidden volumes done, VeraCrypt passphrase
  cap raised from TrueCrypt's 64 to VeraCrypt's 128, and the format/cipher/hash
  of a successful open are now remembered instead of being left buried in a
  long-press menu. Outer-volume protection is done, core and UI, verified at all
  four levels: the container, the location, the unlock dialog, and end to end
  with a destructive control test proving the unprotected write really does
  destroy the hidden volume. Outstanding: hidden volume creation, keyfiles (has
  to be written from scratch)
- **M4 hardening** - `allowBackup=false`, `FLAG_SECURE` on by default, both
  automatic locks, the key-zeroing pass and the wipe fix are done. The zeroing
  pass covered the three paths that leaked key material on the failure branch:
  `EdsContainerBase.close()` skipped `_layout.close()` (the call that zeroes the
  master key) whenever the filesystem close threw; `EdsContainerBase.tryLayout()`
  left the cloned passphrase alive on every wrong-password attempt, which for
  LUKS is every attempt; and `luks.VolumeLayout.tryPassword()` left the
  anti-forensic buffer, the derived key and a rejected master key in the heap.
  Outstanding: no persisted trace that a container has a hidden volume,
  `SecureBuffer.closeAll()` still has zero callers, and the temp folder is
  `getWorkDir()`, which defaults to the empty string - what it resolves to and
  whether it survives a lock are still unmeasured
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
| `KdfTest` | PBKDF2 against published vectors; the generic HMAC agrees byte for byte with the platform's own; per-hash cost | OpenSSL via Python `hashlib` |
| `CipherKatTest` | AES-XTS, RIPEMD-160 and Whirlpool known answers; Serpent and Twofish round-trip and are distinct from AES | OpenSSL |
| `UnsupportedMatrixTest` | the FULL negative matrix, all 41 | desktop VeraCrypt 1.26 |
| `HardeningTest` | both automatic locks default on and can be turned off; the wipe preserves the file length and covers the partial last block; the wipe still deletes | the filesystem itself, and a known-bad build of each arm |
| `HmacNativeMemoryTest` | the PBKDF2 inner loop does not grow the native heap, with `javax.crypto.Mac` in the same run as the positive control that proves the measurement can see a leak | `/proc/self/status` VmRSS |
| `HiddenVolumeProtectionTest` | every write that touches the protected extent is refused and every write that misses it goes through, both write paths, the refusal latches, a truncation below the hidden volume is refused, an empty protected range is rejected, and reads are never refused | an in-memory IO the test reads back byte for byte |
| `OuterVolumeProtectionTest` | a write aimed at the hidden volume is refused and the hidden volume still opens with its original contents; the SAME write with no protection destroys it; a wrong protection passphrase refuses the mount | desktop VeraCrypt 1.26, and the unprotected control |
| `ContainerLocationProtectionTest` | the second passphrase survives the trip from the location to the container and switches protection on; an identical open without it has protection off; an empty field means no protection rather than a failed mount; a wrong one refuses the mount as the message the UI shows; close() drops the passphrase | the container's own protected-range state, and the unprotected control |
| `PasswordDialogProtectionTest` | the unlock dialog offers the protection field for a VeraCrypt container and not for LUKS or while creating one; the layout this device resolves actually carries it; what is typed comes back out; a blank field reads as empty and a never-offered one as absent; the reveal button unmasks both passphrases and destroys neither | the LUKS location as the format control, and known-bad builds of both reveal arms |
| `LocationOpenerBundleTest` | the two Bundle hops between the dialog and the location: what the dialog holds reaches the result bundle and is copied onto the open request, a dialog that never offered the field puts nothing there, and the deliberate asymmetry holds (an empty protection passphrase overwrites a stale one, an empty password does not overwrite a saved one) | the bundle contents themselves, and a known-bad that gives the protection branch the password branch's rule |
| `SettingsKeyLockTest` | a protected setting round-trips; dropping the cached settings key costs nothing but a re-derivation and hands back a different buffer; a saved container password still opens after the lock; clearing the master password erases it rather than dropping the reference; and the WRONG lock, erasing the key buffer without dropping the cache, breaks every protected read AND throws out of the saved-password path | the protected preference itself, and the broken state as an executable known-bad |
| `OpenHintTest` | a hash hint replaces the search with one derivation; a successful open reports the format, cipher and hash it used; those survive the settings round-trip; a hidden open is distinguishable from an outer one | desktop VeraCrypt 1.26, and the container's own progress reporter |

Every arm of `HardeningTest` has been run against a build with that specific
behaviour reverted, because a test of a property that has no visible symptom is
worth exactly as much as the proof that it can go red. Five arms, two known-bad
builds:

| Arm | Known-bad | What it said |
|---|---|---|
| length preserved | upstream `getOutputStream()` body | `expected:<10000> but was:<12288>` |
| tail covered | whole 4 KiB blocks only, partial tail skipped | `the last partial block (bytes 8192..10000) still holds the original plaintext` |
| defaults on | `DefaultSettingsCommon` returning false | `screen-off lock must default on` |
| can be turned off | getters returning a constant instead of reading the preference | `the screen-off preference is not read` |
| wipe deletes | `file.delete()` removed from the `finally` | `wipeFileRnd left the file behind` |

The two wipe arms fail against different builds and pass against each other's,
which is the point: they are two assertions, not one test written twice.

`PasswordDialogProtectionTest` has two arms with known-bads, and neither needed
a build made up for the purpose, because both were written against code that was
already broken.

| Arm | Known-bad | What it said |
|---|---|---|
| reveal unmasks both | `toggleShowPassword` before the fix | `the reveal button left the protection passphrase masked` |
| reveal destroys neither | `EditSB.setText` before the fix | `revealing wiped the passphrase: array lengths differed, expected.length=12 actual.length=0` |

In both runs the other tests passed, which is the half that matters: it says the
known-bad build was still a working build, so the failure was the defect and not
a broken copy.

`LocationOpenerBundleTest` pins one asymmetry that looks like a copy-paste
mistake and is not. An empty PROTECTION passphrase overwrites a stale one,
because the request bundle is reused across attempts and an empty box means the
user cleared it; an empty PASSWORD does not overwrite a saved one, because a
blank password box means "use the one you have". Those two rules sit a few lines
apart, and the obvious tidy-up is to make the second look like the first. Giving
the protection branch the password branch's rule failed exactly one test with
`clearing the field left the previous protection passphrase in force
expected:<0> but was:<23>`, and the other four passed.

`SettingsKeyLockTest` carries its known-bads as tests rather than as reverted
builds, because the wrong version is a call that exists. Two arms close the key
buffer the way `SecureBuffer.closeAll()` would, require the next read to fail,
and then require the supported clear to repair it. If either ever stops
throwing, the memoisation has changed and the reasoning written beside the lock
is stale.

| Arm | Wrong lock | What it said |
|---|---|---|
| protected settings readable after a lock | `getSettingsProtectionKey().close()` | `InvalidSettingsPassword`, which is the app reporting a wrong settings password to someone who never set one |
| a saved container password survives a lock | the same one call | `RuntimeException: key is closed`, thrown out of `ExternalSettings.getPassword` |

That second pair is the one worth having. A saved container password is not
stored in the clear: `setPassword` encrypts it immediately with the SAME
settings protection key the lock drops. So "the lock forgets the settings key"
and "the lock forgets every saved container password" sit one wiring mistake
apart, and only the first is intended. The positive arm goes through a real
`VeraCryptLocation` and its real external settings, because the provider is the
part that could be wired wrong.

`OuterVolumeProtectionTest` carries its own known-bad rather than needing a
reverted build for one. `theSameWriteWithoutProtectionDestroysTheHiddenVolume`
performs the identical write on an identical copy with the wrapper absent, and
requires the hidden volume to come back damaged. Without it, the protected arm
would pass just as happily if the write had been harmless all along.

`UnsupportedMatrixTest` is `@LargeTest` and the runner excludes it unless you
name it, because every fixture in it pays the whole hash sweep twice. The
default run says out loud that it skipped it, and the sampled arm inside
`ContainerFixtureTest` prints the fixtures it did not test. A coverage cut that
leaves no trace reads afterwards as coverage.

The TrueCrypt format has no fixture at all, and the README should not imply
otherwise: every container in the oracle is VeraCrypt. The reason is the tool,
not the format. VeraCrypt 1.26's GUI has a TrueCrypt mode but its command line
does not expose one, so `mkfixtures.sh` cannot produce a TrueCrypt volume.
`tcplay` can, and is packaged, but is not installed on this build host. Until
that is settled, TrueCrypt support here is inherited and unmeasured. It is also
the cheap half of the matrix to test: TrueCrypt uses 1000 iterations (2000 for
RIPEMD-160) against VeraCrypt's 500000, so a whole TrueCrypt matrix would cost
less than one VeraCrypt fixture.

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
