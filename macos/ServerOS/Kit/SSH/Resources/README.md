# Bundled agent binaries

ServerOS installs the agent by **copying it to the server over the SSH
connection it already holds** — not by asking the server to download it. So the
Linux builds live here, inside the app.

| File | Target | Built from |
|---|---|---|
| `serveros-agent-linux-x86_64` | `x86_64-unknown-linux-gnu` | `agent/` at 0.1.0 |

`aarch64` is not yet bundled. Until it is, adding an arm64 server fails with a
message that says exactly that, rather than with a network error — see
`ServerOSError.agentBuildUnavailable`.

## Rebuilding

On a Linux machine of the target architecture (or with a cross toolchain):

```bash
cd agent
cargo build --release
cp target/release/serveros-agent \
   ../macos/ServerOS/Kit/SSH/Resources/serveros-agent-linux-$(uname -m)
```

Then confirm what you copied:

```bash
file   macos/ServerOS/Kit/SSH/Resources/serveros-agent-linux-x86_64
sha256sum macos/ServerOS/Kit/SSH/Resources/serveros-agent-linux-x86_64
```

The upload verifies the SHA-256 of what lands on the server against what left
the Mac, so a truncated transfer fails loudly instead of installing a broken
binary as a privileged service.

## Why a binary is in the repository at all

Checking a build artefact into source control is normally wrong. It is here
because the alternative — a download host — is worse in this specific case: a
lot of the servers worth managing have no outbound internet, and pointing the
installer at a URL that does not exist is how the first real setup attempt
failed. When there is a real release channel, the installer's `--base-url`
path is still there for it, and this directory can go.

The binary is dynamically linked against glibc 2.17+, which covers Ubuntu
22.04/24.04 and Debian 12. A musl static build would widen that; it is not
worth the cross-toolchain setup until a server needs it.
