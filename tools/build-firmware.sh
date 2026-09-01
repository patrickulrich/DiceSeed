#!/usr/bin/env bash
# Reproducible firmware build (ROADMAP item 2): builds BOTH variants
# (compat + classic) inside a throwaway Debian container from a fully
# pinned toolchain, so any machine with Docker produces byte-identical
# .bin files. Same throwaway-container style as tests/run_tests.sh; the
# pins below are the single source of truth for local runs AND for CI
# (the build job in .github/workflows/build.yml calls this script).
# See docs/reproducible-build.md for what that buys you and how to
# verify a released binary against it.
#
# Usage: tools/build-firmware.sh [output-dir] [label]
#   output-dir  where the .bin files + SHA-256SUMS land (default: build/)
#   label       name embedded in the artifacts -- a git tag or short sha
#               (default: short sha of HEAD, "untagged" outside a repo)
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-build}"
LABEL="${2:-$(git rev-parse --short HEAD 2>/dev/null || echo untagged)}"

# ---- Toolchain pins --------------------------------------------------------
# arduino-cli's own tarball is the one download verified by hash rather
# than by HTTPS alone -- it is the tool that decides what everything
# else is. The platform/library versions are the same ones README's
# "Build & flash" documents as tested on hardware.
ARDUINO_CLI_VERSION=1.5.1
ARDUINO_CLI_SHA256=28a8e119c498a25607821c36cb2dc49e8463941b261a0d99091baa7bc692dd2b
ESP32_CORE_VERSION=3.3.11
TFTESPI_VERSION=2.5.43

# Label becomes part of output filenames: keep it filename-safe.
if [[ ! "$LABEL" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "error: label must be filename-safe (A-Z a-z 0-9 . _ -), got: $LABEL" >&2
  exit 1
fi

# SOURCE_DATE_EPOCH: the ESP-IDF app descriptor embeds __DATE__/__TIME__,
# which otherwise makes every build of the same source differ by a few
# bytes (verified: two cold CI builds of one commit differed in exactly
# the timestamp field plus the descriptor's embedded ELF SHA-256 echoing
# it). GCC expands __DATE__/__TIME__ from this variable when set, so it
# is pinned to the commit timestamp -- same commit, same embedded time,
# byte-identical binary. 0 (1970-01-01) outside a git checkout: still
# deterministic, and obviously synthetic.
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct 2>/dev/null || echo 0)"

mkdir -p "$OUT"

# Repo mounted READ-ONLY (the build must not depend on -- or modify --
# the checkout); output dir mounted writable; a named Docker volume
# caches the arduino-cli platform/library downloads so repeat runs do
# not re-fetch ~1GB of toolchain. The cache is keyed by the pins above:
# changing a pin downloads the new versions into the same volume.
docker run --rm \
  -v "$PWD:/src:ro" -w /src \
  -v "$(cd "$OUT" && pwd):/out" \
  -v diceseed-arduino-cache:/cache \
  -e ARDUINO_DIRECTORIES_DATA=/cache/data \
  -e ARDUINO_DIRECTORIES_DOWNLOADS=/cache/downloads \
  -e ARDUINO_DIRECTORIES_USER=/cache/user \
  -e CLI_VER="$ARDUINO_CLI_VERSION" \
  -e CLI_SHA="$ARDUINO_CLI_SHA256" \
  -e CORE_VER="$ESP32_CORE_VERSION" \
  -e LIB_VER="$TFTESPI_VERSION" \
  -e LABEL="$LABEL" \
  -e SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" \
  debian:bookworm-slim bash -eu -c '
    set -e
    apt-get update -qq >/dev/null
    # python3 is not optional: esp32 core 3.x build recipes call it
    # (partition/tool post-processing); bookworm-slim ships without it.
    apt-get install -y -qq curl ca-certificates python3 >/dev/null

    # arduino-cli, pinned + checksum-verified (two spaces are the
    # sha256sum(1) format).
    curl -fsSL -o /tmp/cli.tar.gz \
      "https://downloads.arduino.cc/arduino-cli/arduino-cli_${CLI_VER}_Linux_64bit.tar.gz"
    echo "${CLI_SHA}  /tmp/cli.tar.gz" | sha256sum -c -
    tar xzf /tmp/cli.tar.gz -C /usr/local/bin arduino-cli
    arduino-cli version

    arduino-cli config init --overwrite >/dev/null
    arduino-cli config add board_manager.additional_urls \
      https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
    arduino-cli core update-index >/dev/null
    arduino-cli core install "esp32:esp32@${CORE_VER}"
    arduino-cli lib install "TFT_eSPI@${LIB_VER}"

    # The mounted /out dir is the only way artifacts leave the container;
    # fail loudly if the bind mount ever goes missing rather than letting
    # a later cp fail confusingly.
    [ -d /out ] || { echo "FATAL: /out mount missing" >&2; exit 1; }

    # Build from a scratch COPY of the sketch at a fixed path, not from
    # the read-only mount: the build leaves side-effect directories
    # inside the sketch folder (arduino-cli stages exports under
    # <sketch>/build/<fqbn>/ when artifacts are copied out, and the esp32
    # core post-build hooks run next to it), which cannot be written on a
    # RO mount. The copy directory MUST keep the same name as the sketch
    # folder (DiceSeed/DiceSeed.ino) -- a sketch folder has to contain an
    # .ino of the same name or arduino-cli rejects it. The copy is what
    # the compiler sees, identically on every machine; the mount itself
    # stays the untouched source of truth.
    cp -a /src/DiceSeed /tmp/DiceSeed

    build_variant() {
      name="$1"; extra="$2"
      # A custom --build-path forces a full, cache-independent build
      # (arduino-cli >= 1.0.4) and --clean makes that explicit: nothing
      # from a previous variant, a previous run, or the download cache
      # can reach the artifacts. No --output-dir: it additionally stages
      # a legacy export tree inside the sketch folder.
      arduino-cli compile \
        --fqbn esp32:esp32:lilygo_t_display_s3 \
        --build-property "build.extra_flags=${extra}" \
        --build-path "/tmp/build-${name}" --clean \
        /tmp/DiceSeed

      # The release artifact is the MERGED image (v2.4.8): bootloader +
      # partition table + application in one file, flashed at 0x0 -- one
      # file, one address, the same command for a brand-new board and an
      # update. The core generates it padded to the FULL flash size (16MB
      # for this board); everything after the app is 0xFF filler (the
      # erased state), so the tail is trimmed: find the last real byte,
      # round up to the 4KB sector, truncate. 16MB -> ~450KB, lossless --
      # unwritten flash reads back erased-or-stale-but-unused either way,
      # exactly how every app-only ESP32 update has always behaved
      # (esptool erases only what it writes). The trimming is
      # deterministic, so reproducibility is unaffected. The bare app
      # image (DiceSeed.ino.bin) stays in the build dir for anyone who
      # specifically wants an app-only artifact.
      python3 - "/tmp/build-${name}/DiceSeed.ino.merged.bin" \
               "/out/diceseed-${LABEL}-${name}.bin" <<'PYEOF'
import sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    data = f.read()
last = len(data) - 1
while last >= 0 and data[last] == 0xFF:
    last -= 1
end = min(((last // 4096) + 1) * 4096, len(data))
with open(dst, "wb") as f:
    f.write(data[:end])
print(f"{dst}: trimmed {len(data)} -> {end} bytes")
PYEOF
    }

    # Compat is the default build: build_mode.h guards with #ifndef and
    # defaults DICESEED_COMPAT_BUILD to 1, so the empty extra-flags
    # string IS compat. Classic overrides to 0.
    build_variant compat ""
    build_variant classic "-DDICESEED_COMPAT_BUILD=0"

    cd /out
    sha256sum "diceseed-${LABEL}-compat.bin" "diceseed-${LABEL}-classic.bin" > SHA-256SUMS
    cat SHA-256SUMS
  '

echo
echo "Artifacts in ${OUT}/: diceseed-${LABEL}-{compat,classic}.bin + SHA-256SUMS"
