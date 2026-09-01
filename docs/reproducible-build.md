# Reproducible builds

Someone who can't or won't compile from source has no way to confirm that
a flashed `.bin` matches the published source. The established
airgapped-signing projects (SeedSigner, Krux) treat that as core, not
polish — this is DiceSeed's answer (ROADMAP item 2, shipped in v2.4.7).

The contract: **the same commit, built by this script, produces
byte-identical `.bin` files on any machine.** Everything that could vary
is pinned; everything pinned lives in one place.

## The pins (tools/build-firmware.sh)

| Component | Version | Pinned how |
|---|---|---|
| Build container | `debian:bookworm-slim` | Image tag in the script |
| `arduino-cli` | 1.5.1 | Direct tarball download, **SHA-256 verified in-script** |
| ESP32 Arduino core | `esp32:esp32@3.3.11` | Versioned install (README's tested version) |
| `TFT_eSPI` | 2.5.43 | Versioned install (README's tested version) |
| Board | `esp32:esp32:lilygo_t_display_s3` | LilyGO's dedicated board entry (correct flash/partition map) |

The pins are the single source of truth for local builds **and CI** — the
build job in `.github/workflows/build.yml` runs this same script, so a
green CI checkmark certifies exactly the toolchain described here, and CI
artifacts are byte-identical to what you build locally.

One nondeterminism source is neutralized rather than pinned: the ESP-IDF
app descriptor embeds the compile time (`__TIME__`/`__DATE__`). The
script exports `SOURCE_DATE_EPOCH` (which GCC honors for those macros)
set to the **commit timestamp**, so the same commit always embeds the
same time. This was not theoretical: two cold CI builds of one commit
differed in exactly the timestamp field — and in the descriptor's
embedded ELF SHA-256 echoing it — before this was added. A pleasant side
effect of that embedded ELF hash: any single-byte difference anywhere in
the build is visible in the descriptor, not just in the file digest.

Why the pins matter: this firmware's value proposition is "same rolls →
same mnemonic, verifiably." A build that silently picked up core 3.4.x or
TFT_eSPI 2.6.x tomorrow would produce a binary nobody has ever tested on
hardware. If a pin ever needs bumping, expect the artifact hashes to
change and publish a new release — never let the same tag name refer to
two different binaries.

## Building

```sh
tools/build-firmware.sh [output-dir] [label]
# e.g.
tools/build-firmware.sh build v2.4.7
```

Requires only Docker. The repo is mounted **read-only** into a throwaway
container; build and output directories live outside the sketch (the
`DiceSeed/` subdirectory, per the v2.4.1 layout); each variant is built
with a fixed `--build-path` and `--clean`, so no state from a previous
run, variant, or cache can leak into the artifacts. A named Docker volume
(`diceseed-arduino-cache`) caches the ~1GB of platform downloads so
repeat runs are fast — delete it with `docker volume rm
diceseed-arduino-cache` if you ever want to prove a cold build from
scratch.

Output, in the output dir:

- `diceseed-<label>-compat.bin` — the default (SeedSigner-compatible) build
- `diceseed-<label>-classic.bin` — the hand-auditable bignum build
- `SHA-256SUMS` — SHA-256 of both, exactly as computed at build time

Since v2.4.8 each `.bin` is a **complete image** — bootloader + partition
table + application — flashed at `0x0`, the same command for a new board
and an update. The core generates the merged image padded to the full
16MB flash; the script trims the trailing `0xFF` filler (the erased
state), leaving a ~450KB artifact that writes identically for every
region it covers. The bare app-only image (`DiceSeed.ino.bin`) remains
in the build dir inside the container for anyone who specifically wants
one.

## Verifying a release binary

1. Download the `.bin` and `SHA-256SUMS` attached to the release (the
   release job attaches them automatically when the version bump merges
   to `main`; if they are missing, the artifacts of that release's CI
   run contain the same files).
2. `sha256sum --ignore-missing -c SHA-256SUMS` (or compare by eye).
3. For stronger assurance, build the same tag yourself with the script
   and compare hashes: they must match. If they do, your flashed binary
   is exactly what the published source produces under the pinned
   toolchain — no toolchain trust required beyond Docker itself.

## What this does NOT cover

- **Docker and the host are still trusted.** The container pins the
  userspace, not the kernel; a compromised host compromises the build.
  For an offline seed device, build on a machine you trust, and use the
  CI-published hashes as an independent cross-check (two different
  machines agreeing is meaningfully stronger than one).
- **Hashes confirm *what*; signatures confirm *who*.** The pipeline
  supports PGP-signed releases (`SHA-256SUMS.sig` + signed annotated
  tags) wherever a maintainer has configured a signing key in the `release`
  environment — see [signing.md](signing.md). Repos without a key
  publish unsigned releases; the hash check and this reproducible
  rebuild are the guarantees that remain.
- **Upstream availability.** The script downloads pinned versions from
  `downloads.arduino.cc` and the Espressif/Arduino library indexes at
  build time; those artifacts are version-addressed (the same version
  string is the same bytes), but the downloads themselves can disappear.
  The named cache volume is your friend.

## CI behavior

- Every push and PR: test suite + both variants via this script; each run
  uploads `diceseed-<sha>-firmware` (both `.bin`s + `SHA-256SUMS`) as an
  artifact.
- Every push to `main` that bumps `FIRMWARE_VERSION_BASE` past the latest
  `v*` tag — with the matching `docs/releases/vX.Y.Z.md` present — is
  released **automatically**: CI tags the merged commit, builds both
  variants with this script, creates the GitHub Release with the notes
  file as its body, and attaches both `.bin`s + `SHA-256SUMS`. A bump
  without its notes file fails the job ("no notes, no release"); a
  `workflow_dispatch` dry run rehearses the detection with no side
  effects. The maintainer's whole process is: write the notes, bump the
  version, merge to `main`.
