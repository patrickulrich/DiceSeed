# Signed releases

Hashes prove *what* was built — that the binary you hold is what the
published source produces under the pinned toolchain. Signatures prove
*who* published it — that the release came from a holder of this
project's signing key, not from a compromised pipeline or account. This
repo's pipeline supports both; signing is **opt-in per repository**, so
forks and fresh clones build and release normally without any key, and a
maintainer can enable signing at any time with zero code changes.

## For users: verifying a signed release

If the repository you downloaded from publishes a signing key (look for
`docs/signing-key.asc` and a fingerprint in its README), verify before
trusting the hashes:

```sh
gpg --import docs/signing-key.asc     # or fetch from the maintainer's
                                      # published location; compare the
                                      # fingerprint against the README
gpg --verify SHA-256SUMS.sig SHA-256SUMS
sha256sum --ignore-missing -c SHA-256SUMS
```

Also check the release tag itself: `git verify-tag vX.Y.Z` shows the
same key's signature on an annotated tag. If the repository publishes no
key, releases are unsigned by design — the `SHA-256SUMS` check and the
reproducible-build cross-check ([reproducible-build.md](reproducible-build.md))
are the available guarantees.

## For maintainers: enabling signed releases

The release job already carries the signing logic. Three one-time steps
turn it on; from then on every release is signed automatically.

### 1. Generate the key (on a trusted, ideally offline, machine)

A dedicated signing subkey, with the primary key kept offline:

```sh
# Primary key -- certification only, never leaves this machine
gpg --quick-generate-key "DiceSeed Release <you@example>" ed25519 cert never

# Dedicated signing subkey -- this is what CI will hold
gpg --quick-add-key <PRIMARY_FPR> ed25519 sign never

# Export the pieces:
#   subkey-only private export (the primary becomes a stub even if leaked)
gpg --output signing-subkey.asc --armor --export-secret-subkeys <PRIMARY_FPR>!
#   public key (commit to the repo as docs/signing-key.asc)
gpg --output public.asc --armor --export <PRIMARY_FPR>
```

Leave the subkey **without a passphrase**: in CI a passphrase just
becomes a second secret with identical exposure; the protection is the
dedicated-subkey + offline-primary design. Keep the revocation
certificate (`~/.gnupg/openpgp-revocs.d/<FPR>.rev`) somewhere safe —
it is the kill switch if the subkey ever leaks.

### 2. Store the subkey as an environment secret

The key lives in a GitHub environment called `release`, which scopes it
away from plain branch-push workflows:

```sh
gh secret set SIGNING_KEY --env release < signing-subkey.asc
```

(The `release` environment is referenced by the workflow and
auto-created on first use; creating the secret creates it if needed.
Optionally restrict its deployment branches to `main` in the repo's
environment settings for belt-and-suspenders.)

### 3. Publish the public key + fingerprint

Commit the public key as `docs/signing-key.asc` and add the subkey
fingerprint to the README's verify section, plus wherever you publish
out-of-band (the fingerprint is the actual trust anchor — the repo alone
can't vouch for itself).

### What changes when enabled

- `SHA-256SUMS.sig` — a detached PGP signature over the manifest (which
  lists both firmware images) — is created and attached to every release
- The release tag becomes a **signed annotated tag** instead of a
  lightweight one
- No key configured → an explicit notice in the job log, releases
  publish unsigned with hashes only (this is the default on forks)

### Rotation and revocation

If the subkey leaks: revoke it with the stored revocation certificate,
publish the revocation, generate a new subkey under the same primary
key, replace the `SIGNING_KEY` secret and `docs/signing-key.asc`. Users
re-verify against the new fingerprint; prior releases remain verifiable
with the old public key unless you explicitly revoke trust in them.
