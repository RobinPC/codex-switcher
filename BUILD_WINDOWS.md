# Building Codex Switcher on Windows

This hardened fork publishes Windows x64 builds only. Use PowerShell for all commands below.

## 1. Install the prerequisites once

Install these components before building:

1. Node.js LTS from <https://nodejs.org/>.
2. Microsoft C++ Build Tools from <https://visualstudio.microsoft.com/visual-cpp-build-tools/>. Select **Desktop development with C++** in the installer.
3. Rust through rustup from <https://rustup.rs/> or with `winget install --id Rustlang.Rustup`.
4. Microsoft Edge WebView2 Runtime. It is normally already installed on supported Windows 10 and Windows 11 systems.

Open a new PowerShell window after installation and run:

```powershell
rustup default stable-msvc
npm install --global pnpm@12.3.4

node --version
npm --version
pnpm --version
rustc --version
cargo --version
```

The `pnpm` version must be `12.3.4`. Do not install a global `tauri` command; the repository supplies the required Tauri CLI version.

## 2. Install the locked dependencies

```powershell
Set-Location D:\Development\codex-switcher
pnpm install --frozen-lockfile
```

Always keep `--frozen-lockfile`. It prevents an installation from silently changing the reviewed dependency versions.

## 3. Run the security checks and tests

Install `cargo-audit` once:

```powershell
cargo install cargo-audit --locked --version 0.22.2
```

Run the same important checks used by GitHub:

```powershell
Set-Location D:\Development\codex-switcher
pnpm audit --audit-level high
cargo audit --file src-tauri\Cargo.lock
pnpm build
cargo test --manifest-path src-tauri\Cargo.toml --locked
```

Do not build a release if one of these commands fails.

## 4. Build a local Windows executable

Use this command for a local executable without installers or signing:

```powershell
Set-Location D:\Development\codex-switcher
pnpm tauri:win build --no-bundle --no-sign
```

The executable is created at:

```text
D:\Development\codex-switcher\src-tauri\target\release\codex-switcher.exe
```

This local file is not Authenticode-signed, so Windows SmartScreen may show a warning. The file can be checked with:

```powershell
Get-FileHash .\src-tauri\target\release\codex-switcher.exe -Algorithm SHA256
Start-MpScan -ScanType CustomScan -ScanPath .\src-tauri\target\release\codex-switcher.exe
```

## 5. Build unsigned local installers

For local NSIS and MSI installer packages:

```powershell
Set-Location D:\Development\codex-switcher
pnpm tauri:win build --no-sign
```

The installer artifacts are written below:

```text
D:\Development\codex-switcher\src-tauri\target\release\bundle\
```

MSI creation requires the Windows **VBSCRIPT** optional feature. Enable it through **Settings > Apps > Optional features > More Windows features** if the WiX tools report an error.

## 6. Publish an official fork release

Do not publish a locally built unsigned installer as an official update. Use the protected GitHub workflow:

1. Confirm that the reviewed version change is on the current `main` branch.
2. Confirm that the **Security gate** workflow is green for that commit.
3. Open <https://github.com/RobinPC/codex-switcher/actions/workflows/build.yml>.
4. Select **Run workflow**.
5. Enter a version such as `v0.2.18`. It must exactly match the version in `package.json`.
6. Enter a short release note.
7. Review the selected commit when GitHub requests approval for the protected `release` environment.
8. Approve only if the commit is the expected current `main` commit.

GitHub then builds the Windows installers, signs the Tauri updater artifacts with the fork key, publishes the release under `RobinPC/codex-switcher`, and creates `latest.json` for in-app updates.

Never download an executable from the upstream author's release page for use as a fork release. Upstream changes must enter through a reviewed source-code pull request.

## Troubleshooting

### `pnpm` is not recognized

```powershell
npm install --global pnpm@12.3.4
```

Close and reopen PowerShell after installation.

### `tauri` is not recognized

This is expected when entering `tauri` directly. Use:

```powershell
pnpm tauri:win build --no-bundle --no-sign
```

### MSVC linker or `link.exe` errors

Open the Visual Studio Installer, modify **Build Tools 2022**, and ensure **Desktop development with C++** and a Windows SDK are installed. Then open a new PowerShell window.
