# Building and flashing details

Everything the README's *Building from source* section points here for.
If you just want DiceSeed on a board, you want the README's
*Installing DiceSeed* — the release `.bin` files install in one command
with no toolchain at all. For a build that matches the release binaries
byte-for-byte, use `tools/build-firmware.sh` (see
[reproducible-build.md](reproducible-build.md)) — the directions below
are for development with your own toolchain, where compile + flash is a
single fast step.

## Getting the code onto disk

`git clone https://github.com/Lexcat25/DiceSeed.git`, or use GitHub's
"Download ZIP". Either way the sketch lives in the `DiceSeed/`
subdirectory — open `DiceSeed/DiceSeed.ino` in the Arduino IDE. Since that
folder is named `DiceSeed`, matching the `.ino`, the IDE opens it directly
with every header (`build_mode.h`, `diceseed_core.h`, `bip39_wordlist.h`,
`tft_setup.h`, `touch.h`) alongside it. (Before v2.4.1 the sketch sat at
the repo root, and a ZIP download — which unpacks to
`DiceSeed-<version>/`, not `DiceSeed/` — triggered a
`fatal error: build_mode.h: No such file or directory` for anyone not
using `git clone`. The `DiceSeed/` subdirectory is the fix.)

## Arduino IDE

1. Install [Arduino IDE](https://www.arduino.cc/en/software) (2.x) or
   [`arduino-cli`](https://arduino.github.io/arduino-cli/).
2. Add the ESP32 board index:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
   (Preferences → Additional Board Manager URLs), then install the **esp32**
   platform (tested against 3.3.11).
3. Install the **TFT_eSPI** library (tested against 2.5.43) via Library
   Manager.
4. Board: **LilyGo T-Display-S3** (`esp32:esp32:lilygo_t_display_s3`) —
   the `esp32:esp32` platform ships a dedicated board entry for this exact
   board (search "T-Display-S3" in Boards Manager), which also gets the
   flash size (16MB) and partition table right. The generic "ESP32S3 Dev
   Module" entry also compiles this sketch, but under different
   flash/partition defaults that don't match what's actually on the board.
5. Open `DiceSeed/DiceSeed.ino` and compile/upload. No other Tools-menu
   settings need changing — the sketch opens no serial port, so the USB CDC
   options don't matter either way.

## arduino-cli

The same thing with `arduino-cli`, run from inside the `DiceSeed/` sketch
folder (`cd DiceSeed` from the repo root):

```sh
# one-time setup
arduino-cli config add board_manager.additional_urls \
  https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json
arduino-cli core update-index
arduino-cli core install esp32:esp32
arduino-cli lib install TFT_eSPI

# build (compat is the default; add the --build-property line for classic)
arduino-cli compile --fqbn esp32:esp32:lilygo_t_display_s3 .
arduino-cli compile --fqbn esp32:esp32:lilygo_t_display_s3 \
  --build-property "build.extra_flags=-DDICESEED_COMPAT_BUILD=0" .

# flash -- find your port first
arduino-cli board list
arduino-cli upload -p /dev/ttyACM0 --fqbn esp32:esp32:lilygo_t_display_s3 .
```

On Linux your user needs to be in the `dialout` group to open the serial
port (`sudo usermod -aG dialout $USER`, then log out and back in).

## The tft_setup.h story

You do **not** need to hand-edit TFT_eSPI's own `User_Setup_Select.h`.
This repo ships `tft_setup.h` in the sketch folder, which TFT_eSPI
auto-detects and loads on its own (`__has_include(<tft_setup.h>)` —
TFT_eSPI's own documented mechanism, see that file's comments) with the
exact ST7789/8-bit-parallel pin configuration this board actually uses.
Without it, TFT_eSPI's out-of-the-box default targets a completely
different display and pin set (ILI9341 over SPI) — it still **compiles
clean**, it just drives nothing on real hardware, which is why this file
matters even though nothing about it is visible from a successful build
log.

## Hardware-verified versions

Confirmed working on real hardware as of v1.2.0 (display renders
correctly), v2.0.1 (compat build's entropy matched both SeedSigner and
iancoleman.io on the same rolls; the two-button wipe hold works correctly
— a v2.0.0 regression in that gesture was found and fixed in v2.0.1, see
the version history in `DiceSeed.ino`), v2.1.0 (the backup-verification
quiz), v2.2.0 (tap-to-enter rolls on a Touch board, and the same binary
falling back to buttons on a non-touch board — both confirmed on real
hardware), and v2.3.0 (the word-count menu as tap cells on a Touch board,
including BTN2's refusal to start an unchosen session), and v2.3.1 (BTN2's
refusal to commit an unselected roll — confirmed on the Touch board; the
non-touch white-until-chosen face rendering from the same change is
compile-verified only, no non-touch board was on hand), and v2.3.2 (the
both-button leave-rolling escape hatch and its confirm screen — confirmed
on the Touch board), and v2.3.3 (quiz candidate cells and word-page paging
cells — confirmed on the Touch board via a full 50-roll session), and
v2.4.0 (a back cell on the touch roll screen — confirmed on the Touch
board), and v2.4.1 (repository layout only: the sketch moved into a
`DiceSeed/` subdirectory so "Download ZIP" opens cleanly — no firmware
change, byte-for-byte identical to v2.4.0), and v2.4.2-v2.4.7 (the
roll-grid select/flash color language, the all-words backup quiz with its
summary, and the hex flow screen — confirmed on the Touch board; the
button-edge markers via a forced-non-touch build on the same chassis;
plus the CI/reproducible-build/release pipeline, confirmed by its own
runs), and v2.4.8 (full-image release install — the merged v2.4.8 compat
image flashed at `0x0` straight from the release, boot chain included —
confirmed on the Touch board), and v2.4.9 (the security-surface
warnings and the unified cell language — confirmed on the Touch board).

## Touch-controller hardware notes

The touch driver (documented at length in `DiceSeed/touch.h`) was
verified on both board variants before it was written:

- The controller is a **CST816-family part at I2C address 0x15**. LilyGO
  also ships boards with a **CST328 at 0x1A**, which this does *not*
  drive — such a board reports "no touch" and falls back to the buttons.
  That is the correct degradation, not a failure. LilyGO's own example
  cannot tell the two apart either; it asks you to try one and switch if
  touch misbehaves.
- Presence **must** be probed with a bare address ACK. The chip sits in
  standby until a touch event and will not answer a register read before
  then, so reading its ID register at boot reports "absent" on a
  perfectly good panel.
- The chip **auto-sleeps after 2 seconds** of no touch (register 0xF9,
  factory default) and stops answering while asleep. Register 0xFE
  disables that; the write is retried on the first read the chip does
  answer, since at boot it may already be asleep and reject the write
  itself.
- Coordinates arrive in the panel's native 170×320 portrait frame, so
  they need rotating for the landscape UI: `display_x = native_y`,
  `display_y = 169 - native_x`.
- The driver is hand-rolled rather than pulling in TouchLib. Once the
  probe is an address ACK and a read is 7 bytes from register 0x00, a
  large dependency buys nothing and widens what an auditor has to read.
