# Security policy

Kestrel holds secrets that people cannot afford to lose silently. Reports about
the cryptography, the storage format, the IPC surface and the sync service are
welcome and will be taken seriously.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Advisories → Report a
vulnerability** on this repository. That channel is private to the maintainers
and does not open a public issue.

Do not open a public issue for anything that could be exploited before a fix
exists. If private advisories are unavailable, contact a maintainer through
their GitHub profile.

A useful report contains:

- the commit or version (`0.1.x`),
- the platform and how the build was produced,
- the steps that reach the bug, ideally a proof of concept against a throwaway
  vault,
- what an attacker gains (plaintext? a key? a replay? code execution?),
- whether the vault must already be unlocked.

## What to expect

- Acknowledgement within 7 days.
- A severity assessment and a fix plan, or a reasoned "not a vulnerability"
  reply, within 30 days.
- Credit in the advisory and the release notes unless you ask otherwise.
- No bug bounty: this is an unsponsored project.

Please give a fix 90 days before publishing details, or coordinate with us if
the issue is being exploited.

## Supported versions

The latest commit on `main` and the latest tagged release. `0.1.x` is the only
line that exists today; older tags are not patched.

## In scope

- `src-tauri/core`: Argon2id derivation, HKDF subkeys, XChaCha20-Poly1305
  sealing, the AAD binding, key rotation, session and auto-lock, clipboard
  wipe, the plaintext search projection.
- The typed IPC surface (`src-tauri/src/commands*.rs`) and the Tauri shell:
  command allow-list, WebView2 CSP, file dialogs, the URL opener.
- The local interfaces that hand secrets out: the CLI/SDK named pipe and its
  per-session token, the MCP server and its grants, the SSH agent, the browser
  bridge and native-messaging host, the passkey provider.
- `kestrel-sync`: the wire protocol, request signing, device enrolment and
  withdrawal, storage of ciphertext.
- Import/export (`1PUX`, JSON, CSV), the recovery PDF and recovery-code path.

## Out of scope

- Compromise of the machine, the OS account, the TPM or the Windows Hello
  prompt itself, and anything that needs administrator rights on an unlocked
  machine.
- Vulnerabilities in dependencies, unless Kestrel's use of them turns a benign
  bug into a key or plaintext leak. Version bumps are still appreciated.
- Denial of service against a self-hosted sync instance that the operator
  exposed without rate limits or body caps.
- Reports produced solely by a scanner with no demonstrated impact.

## Known limitations, stated instead of hidden

These are documented in `README.md`, `ROADMAP.md`, `DESIGN.md` §9 and §6:

- Passkey creation and assertion are implemented, but Windows does not route
  WebAuthn ceremonies to a third-party provider; the end-to-end path through
  Windows is unproven.
- Binary attachments are stored locally and are not synced.
- The installer is not code-signed, so Windows SmartScreen warns on first run.
- No independent third-party audit of this code has been performed. The
  cryptography is written against public specifications (RFC 9106, RFC 5869,
  XChaCha20-Poly1305, RFC 6238) and covered by tests, but tests are not an
  audit.
