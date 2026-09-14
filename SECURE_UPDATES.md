# Secure fork maintenance

This fork deliberately does not install release artifacts from the upstream repository. The Tauri updater accepts only artifacts published by `RobinPC/codex-switcher` and signed with this fork's private key.

## Trust boundaries

- OAuth tokens and API keys are stored in the operating-system credential store. `accounts.json` contains metadata and empty credential fields only.
- The hardened fork has no browser/LAN backend and exposes no credential-export commands. Legacy imports remain available only for migrating existing backups.
- The release signing key is not stored in Git. GitHub receives it only through the protected `release` environment.
- Upstream commits are proposed as pull requests. They are never merged or released automatically.
- Pull requests build the frontend, test the Rust backend, review dependency changes, and summarize security-sensitive files.
- GitHub Actions are pinned to full commit hashes. Dependabot proposes action updates for review.
- Releases are built for Windows only and must originate from the current `main` commit with a tag matching the application version.

## Reviewing an upstream update

1. Open the PR created by `Propose upstream update`.
2. Read the `Security impact` job summary before the general diff.
3. Inspect every change to authentication, storage, HTTP endpoints, process execution, Tauri permissions, updater settings, dependencies, and workflows.
4. Confirm that `src-tauri/tauri.conf.json` still points to `RobinPC/codex-switcher` and contains this fork's public update key.
5. Confirm that `src-tauri/src/auth/storage.rs` still removes credentials from the disk representation and fails closed if the credential store is unavailable.
6. Merge only after all required checks pass and the sensitive diff is understood.
7. Publish a release only after the reviewed update has landed on `main`.

## Release signing and recovery

The encrypted local recovery copy is stored outside the repository:

- `C:\Users\Gebruiker\.codex-switcher-maintenance\tauri-signing.key`
- `C:\Users\Gebruiker\.codex-switcher-maintenance\tauri-signing-password.dpapi`

The password file is encrypted for the current Windows user with DPAPI. Keep both files in a private backup. Losing both the local recovery copy and the GitHub environment secrets requires rotating the public key and manually reinstalling the application; existing installations cannot trust artifacts signed by a replacement key.

To make a release, run the `Build & Release` workflow with an explicit version and release note, then approve the `release` environment deployment after checking the commit. Never copy the private key into the repository, an issue, a PR, or a workflow file.
