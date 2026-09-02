# Security policy

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Use GitHub's private reporting: this repository's **Security tab →
"Report a vulnerability"** button. Reports go only to the maintainers,
encrypted in transit, and can be turned into coordinated security
advisories.

<!-- MAINTAINER TODO (v2.5.0): the button requires "Private vulnerability
     reporting" enabled under Settings → Code security and analysis.
     Enable it (and Security advisories), then delete this comment.
     Until then, this file documents the intended channel. -->

<!-- MAINTAINER TODO: confirm or adjust these targets (they follow the
     field standard used by SeedSigner and Krux). -->
We aim to respond within one week and patch within 90 days.

### What to include

- The on-screen version string (e.g. `v2.4.9-compat` — this also
  identifies the build variant)
- A description of the vulnerability and its impact
- Steps to reproduce, ideally with a proof of concept

## Scope

This policy covers the DiceSeed firmware and its build/release pipeline
(`tools/build-firmware.sh`, CI workflows). The trust model and known
physical limitations (USB-JTAG RAM exposure, battery-power guidance) are
documented in README → *What DiceSeed is for* and *Security model* —
those are design documentation, not vulnerabilities, but errors in them
are in scope.

## Supported versions

<!-- MAINTAINER TODO: confirm or adjust. -->
The latest release is supported. Older releases: best effort. Updating
is one command — see README → *Installing DiceSeed*.
