# DiceSeed

Offline, air-gapped dice-roll → BIP39 seed phrase generator for the
[LilyGO T-Display S3](https://www.lilygo.cc/products/t-display-s3) — plain
or Touch variant, one firmware for both.

You physically roll a d6, enter each result on the board's two buttons (or
tap it out on a Touch board), and the firmware turns your rolls into a
standard 12- or 24-word BIP39 mnemonic — the same kind of phrase a hardware
wallet shows you, generated from entropy *you* supplied and can audit, not
a hardware RNG you have to trust blindly.

## What DiceSeed is for (and what it isn't)

DiceSeed is a **generator**: it turns entropy you supplied and can audit
into a standard BIP39 phrase. It is not a signer, not a wallet, and not a
place to keep anything.

The intended flow is: run it **on battery power with no USB cable
attached**, roll and enter your dice, write the phrase down, verify it
(the built-in backup check, plus an optional
[cross-check](#cross-checking-your-output)), then load that phrase into a
proper hardware signer for actual custody. Once you've written the phrase
down and wiped the device, DiceSeed has no further role.

It is **not** a substitute for a Coldcard / SeedSigner / Blockstream Jade
when it comes to holding funds:

- The T-Display S3's USB port is a native USB-Serial-JTAG peripheral,
  enabled in silicon, so anyone with a cable and OpenOCD can halt the CPU
  and read RAM while a phrase is on screen (see
  [Security model](#security-model)). A device that stores nothing and
  signs nothing is a smaller target — but only because it does less.
- The ESP32-S3 has WiFi and Bluetooth radios physically present on the
  board. This firmware never initializes either one, and the repo contains
  no radio code at all — but "no radio in the firmware" is not the same as
  "no radio on the board." Someone who needs the latter guarantee wants a
  different device.

If that trade is acceptable — you want to supply and verify your own
entropy by hand, on a cheap device, and move the result into real
custody — that's exactly the job this does.

## Why dice instead of the chip's own RNG?

Because then nothing has to be trusted except a defined, checkable
conversion from your rolls to entropy — no hardware RNG, no radio, ever,
is mixed in (see [Security model](#security-model)). There are two builds
of that conversion, trading two different kinds of trust against each
other — see [Build variants](#build-variants).

## Hardware

- LilyGO T-Display S3 — **either the plain or the Touch version**. Uses the
  board's ST7789 display (170×320, 8-bit parallel bus) and its two built-in
  buttons (GPIO0, GPIO14).
- **One firmware serves both boards.** On boot it probes for a capacitive
  touch controller; if one answers, the roll-entry screen adds a tap grid. If
  not, everything behaves exactly as it always has. The buttons work on every
  board either way — touch is additive, never required.
- USB-C cable for flashing. **Not required afterward** — see the security
  note about running on battery power for actual use.

## Build variants

One codebase, one repo, two firmware builds — selected by a single flag in
`build_mode.h` (`DICESEED_COMPAT_BUILD`). This exists because a local BTC
group wanted a way to trust this tool anchored to two things they already
trust: [iancoleman.io](https://iancoleman.io/bip39) and
[SeedSigner](https://seedsigner.com). Everything except the dice→entropy
step — display, buttons, wipe, wordlist, the BIP39 checksum step — is
identical between the two; that's deliberate, so there's only one thing to
independently review twice, not two whole codebases.

| | **Compat** (default, `DICESEED_COMPAT_BUILD=1`) | **Classic** (`DICESEED_COMPAT_BUILD=0`) |
|---|---|---|
| Roll → entropy | SHA-256 of the literal roll digits (`"1"`-`"6"`, no separator), low N bits of the digest | Whole roll sequence as one base-6 positional number, low N bits taken |
| Hand-auditable | No — SHA-256 isn't hand-computable | Yes — pencil-and-paper, in principle |
| Same rolls on a real **SeedSigner** unit | **Identical mnemonic** (verified against SeedSigner's own published test vectors) | Different mnemonic |
| Verifiable against **iancoleman.io** | Via the on-screen raw-entropy hex — not its Dice mode | Via the on-screen raw-entropy hex — not its Dice mode |

Neither variant is "more correct" — pick based on which property matters
more for a given device. **Compat is the default** because the point of a
group standardizing on this device is cross-checkable output, and that
should be what people get without touching anything; someone who
specifically wants to redo the whole derivation by hand wants **classic**
instead.

The menu screen's version string shows which one is actually flashed
(`v2.4.9-classic` / `v2.4.9-compat`) — always check it after flashing,
especially if you're maintaining both builds across multiple boards. How
to build each variant: [Building from source](#building-from-source).

## Installing DiceSeed

Installing is one command and takes about a minute — and the exact same
steps update an older DiceSeed and set up a brand-new board.

### 1. Get the firmware

Download from the project's
[Releases page](https://github.com/Lexcat25/DiceSeed/releases). You want
three files:

- `diceseed-vX.Y.Z-compat.bin` — the default build (see
  [Build variants](#build-variants))
- `SHA-256SUMS`
- `SHA-256SUMS.sig` — the maintainer's signature over the sums

(`-classic.bin` is the alternative build — same steps, different
filename. Picking "wrong" is harmless: same hardware either way, reflash
the other one.) Each release `.bin` is a **complete image** — bootloader,
partition table, and application together.

### 2. Get the tools on your computer

```sh
pip install esptool
```

Any machine with Python 3 works — no Arduino toolchain, no compiling.
Signature verification additionally needs [GPG](https://gnupg.org/)
(preinstalled on most Linux distros; macOS: `brew install gnupg`;
Windows: [Gpg4win](https://gpg4win.org/)). On Linux your user needs the
`dialout` group to open the board's serial port
(`sudo usermod -aG dialout $USER`, then log out and back in), and the
USB-C cable must carry data, not charge-only.

### 3. Verify before you flash

Two checks, in order: *who published the release*, then *that your
download matches it*.

**The signature** — proves the release came from the maintainer's key:

```sh
gpg --import docs/signing-key.asc          # from the repo, or the
                                           # maintainer's published copy
gpg --verify SHA-256SUMS.sig SHA-256SUMS   # expect: "Good signature"
```

The signature is only as trustworthy as the **key fingerprint** — compare
it against the one the maintainer publishes out-of-band (project
channels), not just against the copy in the repo, which a compromised
repo could swap.

**The hashes** — prove your download is exactly what was published:

```sh
sha256sum --ignore-missing -c SHA-256SUMS
# expected output: diceseed-vX.Y.Z-compat.bin: OK
```

(Windows PowerShell: `CertUtil -hashfile diceseed-vX.Y.Z-compat.bin
SHA256`, then compare to the matching line in `SHA-256SUMS` by eye.)

**No `SHA-256SUMS.sig` in the release?** That repository publishes
unsigned — the hash check plus a
[reproducible rebuild](docs/reproducible-build.md) are the available
guarantees. The full story, including checking the release tag itself
(`git verify-tag`), is in [Signing](docs/signing.md).

### 4. Plug in the board and flash

Connect the T-Display S3 by USB-C and run:

```sh
esptool write-flash 0x0 diceseed-vX.Y.Z-compat.bin
```

You'll see it connect, erase, write (~5 seconds), report "Hash of data
verified", and hard-reset the board — which boots straight to the
DiceSeed menu. That same one command is also every future update.

**If something goes wrong:**

- *No port found:* list candidates (`ls /dev/ttyACM*` on Linux; Device
  Manager on Windows) and pass it explicitly —
  `esptool --port /dev/ttyACM0 write-flash 0x0 <file>.bin`
- *A failed or interrupted flash is never a dead board.* The ESP32-S3's
  download mode lives in silicon — hold **BOOT** while pressing **RST**
  (or while plugging in) and the chip accepts a fresh flash over USB no
  matter what the flash contains. Just run the command again.
- *Second-hand board, or want a provably clean chip?* `esptool
  erase-chip` once before your first flash wipes all 16MB to the erased
  state; regular installs never need it (DiceSeed keeps secrets in RAM
  only, so ordinary updates leave nothing behind).

## Using it

1. Power on → menu: toggle 12-word (50 rolls) / 24-word (99 rolls) with
   button 1, confirm with button 2. **On a Touch board** the two counts are
   tap cells — tap one to light it, tap the same one again to start.
2. For each roll: cycle the face 1–6 with button 1 to match your physical
   die, confirm with button 2. The first button-1 press lights the current
   face (1 after each commit); each further press advances it — so a roll
   of N takes N presses. An unselected press of button 2 is refused with a
   red hint rather than silently recording the default. The face shows
   white until selected, green once chosen. Long-press button 2 to go back
   a roll if you mis-entered one. **On a Touch board** you can instead tap
   the face directly — and tap the `<` cell at the top-left to go back a
   roll. A yellow banner on this screen reminds you of the physical rule:
   **USB cable disconnected, running on battery.** **To abandon a
   session**, hold both buttons for 2 seconds: a confirm screen offers
   Cancel (every entered roll kept) or Wipe & return to the menu (RAM
   scrubbed, device reboots).
3. After the last roll, a one-time **"Classified Info!" acknowledgment**
   (orange border, SeedSigner's dire-warning convention) appears before
   any words are shown: *keep your seed words private and away from all
   online devices, no USB cable attached.* Dismiss it with "I understand"
   (the button on a Touch board, button 2 otherwise). It shows once per
   generation, and the word pages keep a thin orange border the whole
   time the phrase is on screen.
4. The mnemonic is shown, four words per screen (button 2: next page;
   **on a Touch board** the `<`/`>` cells at the right edge page back and
   forward — `<` is ignored on page 1, and `>` on the last page opens the
   **raw-entropy hex screen** below). A red warning appears if every
   single roll came back identical — a sanity check, not a hard stop.
5. Next comes the **backup quiz that checks every word** — all 12 or all
   24, one at a time. Each check presents the 3 candidates (the real word
   plus 2 decoys) — one at a time on button boards, or as three tap cells
   on a Touch board (tap one to light it, tap it again to lock in); cycle
   with button 1, lock in your pick with button 2, and it tells you
   right/wrong — a wrong answer draws a red border, because a wrong word
   on paper is a security failure, not a quiz score. **On a Touch board**
   the quiz starts from the hex screen: `>` (or button 2) there begins
   verification, `<` goes back to the words. This is a genuine blind pick,
   not a "here's the answer, compare it yourself" re-display — it's meant
   to catch "I misread the word the first time and wrote down the wrong
   one confidently," the more common and more serious way a written backup
   goes wrong. After the last word a summary screen reports **"All 12/24
   words verified. Your backup matches this seed."** — or lists every word
   number that did not match, so you can correct exactly those against the
   word list — then returns to page 1.
6. **Button 1** on the result screen (word pages, or between quiz
   checkpoints once you've locked in an answer) toggles to a **raw
   entropy (hex)** view — the intermediate bytes your rolls produced,
   before the BIP39 checksum and word lookup. **On a Touch board** the
   hex view instead sits in the flow — `>` on the last word page shows it
   before the quiz — and button 1 mirrors the `<` cell (back a page). Its
   headline says it plainly: **this IS your private key** — never
   photograph it or type it into an online device; paste it only into a
   BIP39 tool's raw-entropy field (see
   [Cross-checking your output](#cross-checking-your-output)), and treat
   viewing it with the same care as the phrase itself.
7. **Hold both buttons for 2 seconds** to wipe RAM and reset back to the
   menu. This is the only way to leave the result screen; there's no
   "start a new one without wiping" shortcut, deliberately.

**The color language** (one grammar, firmware-wide): **white** = armed /
selected, **green** = committed (a momentary flash), **yellow** = caution
— act now (USB banner, entropy headline), **orange** = dire (the gate,
the word-page border while the phrase is exposed), **red** = something is
already wrong (failed checks, wipe).

**Touch conventions:** everything that commits a choice (counts, faces,
quiz words, cancel/wipe) uses the two-tap rule — first tap arms (white),
second tap commits (green flash); everything reversible (page `<`/`>`,
the back cell, the gate's "I understand") is single-tap. Taps in the gaps
between cells are ignored, never snapped. The buttons work identically
alongside touch on every screen. The both-button wipe hold is
deliberately button-only — a safety interlock shouldn't be triggerable by
a stray swipe.

## Building from source

Only needed for development, or to verify releases independently — if you
just want DiceSeed on a board, see
[Installing DiceSeed](#installing-diceseed).

- **Reproducibly** (recommended when the result matters):
  `tools/build-firmware.sh` builds both variants in a throwaway Docker
  container from a pinned toolchain, byte-identical to the release
  binaries — [Reproducible builds](docs/reproducible-build.md).
- **With your own toolchain** (Arduino IDE or `arduino-cli`, board
  selection, the `tft_setup.h` story, the hardware-verified version
  list, and the touch-controller hardware notes):
  [Building and flashing details](docs/building.md).

## Security model

- No WiFi or Bluetooth code anywhere in this repo — the ESP32 core never
  brings either radio up.
- Rolls and the mnemonic live only in RAM. Nothing is ever written to
  flash, NVS, or Serial (`Serial.begin()` is never called).
- Sensitive buffers are cleared with `mbedtls_platform_zeroize()` (not
  `memset`, which a compiler can optimize away as a dead store) at boot and
  before the wipe-triggered reset — including the raw entropy buffer kept
  for the hex display.
- Entropy comes **only** from the dice rolls you enter — enforced since
  v2.3.1, not just stated: an unselected roll cannot be committed. The one
  place the hardware RNG (`esp_random()`) is used at all is picking which
  *wrong* words to show as quiz decoys — no bearing on the mnemonic.
- The **compat** build's SHA-256 entropy step isn't a new trust
  dependency: the BIP39 checksum step requires SHA-256 in *every* build,
  so compat reuses an already-required call.

**What this cannot protect against:** the T-Display S3's USB port is a
native USB-Serial-JTAG peripheral, enabled by default at the silicon
level. Anyone with a USB cable and OpenOCD can halt the CPU and dump RAM
while a phrase is on screen, regardless of anything the firmware does. Run
it on battery power with no USB cable attached whenever you're actually
entering rolls or reading back a phrase.

**Known, accepted limitation (classic build only):** the 12-word/50-roll
mode has a small modular bias (effective min-entropy ≈127.4 bits) because
`6^50` gets folded down via `mod 2^128` — the same tradeoff the reference
iancoleman.io dice method makes, kept for hand-auditability. The
24-word/99-roll mode has **no** such bias (`6^99 - 1 < 2^256`). See
`diceseed_core.h` for the exact math.

## Testing & releases

- **Tests**: `tests/run_tests.sh` runs the BIP39 core against the official
  trezor test vectors, an independent Python dice oracle, and SeedSigner's
  published dice vectors — in a throwaway Docker container, no toolchain
  needed. CI runs it plus both firmware builds on every push and PR.
- **Reproducible builds**: `tools/build-firmware.sh` — pinned toolchain,
  byte-identical to release binaries:
  [docs/reproducible-build.md](docs/reproducible-build.md).
- **Automated releases**: *write the notes* (`docs/releases/vX.Y.Z.md`),
  *bump the version*, *merge to main* — CI tags, builds, signs, and
  publishes with hashes and `SHA-256SUMS.sig` where a signing key is
  configured ([docs/signing.md](docs/signing.md)).

## Cross-checking your output

**Don't type your raw dice rolls into iancoleman.io's "Dice" mode
expecting a match** — BIP39 never standardized dice→entropy, and
iancoleman uses yet another convention. Two working paths, both from the
on-device raw-entropy hex screen:

- **iancoleman.io (either build):** paste the on-screen hex — not the
  rolls — into its **Hex** entropy field, using a downloaded offline copy,
  and only with a test roll sequence.
- **SeedSigner (compat only):** enter the same physical rolls into a real
  SeedSigner's dice-entropy feature — compat's derivation matches it
  exactly, so the mnemonic should be identical. Two independently
  developed implementations agreeing from the same raw input is the
  strongest check available.

## Security

Found a vulnerability — or any bug that could affect the security of
someone's funds? Please don't open a public GitHub issue; report it
privately following the process in [SECURITY.md](SECURITY.md).

## Roadmap

Work in progress and open design questions live in
[`ROADMAP.md`](ROADMAP.md) — notably whether the compat/classic build
mode should become a runtime menu choice instead of a compile-time
flag (deliberately undecided).

## License

MIT — see `LICENSE`.
