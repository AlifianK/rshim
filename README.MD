# `rshim`

rshim is the [`shim`](https://github.com/71/scoop-better-shimexe) program written in rust.

## Why this exist?
There are several versions of `shim`:
1. the official [`shim.cs`](https://github.com/lukesampson/scoop/blob/master/supporting/shimexe/shim.cs) was written in c# and required an instantiation of a .NET command line app every time it was started therefore is slower than directly executing. And it dose not handle Ctrl+C event correctly.

2. [`shim.c`](https://github.com/71/scoop-better-shimexe) is ok with performance and Ctrl+C event handling,but sometimes suffer memory violation (randomly exited with return code `3221226356`).

3. [`shim.cpp`](https://github.com/kiennq/scoop-better-shimexe) didn't work on my machine, calling it with any executable result in an infinite recursion of creating subprocess until eating all memory for unknown subtle reason.

### `rshim` :
1. less probability with bug and undefined behavior.
2. properly handle variety errors.
3. friendly error message.
4. properly handle Ctrl+C events.
5. properly handle utf-8 with or without bom in shim file.

## Installation
First install [rust](https://rustup.rs/)
```shell
cargo build --release
```
Close any running process with existed shim.
then
```shell
./repshims.bat
```

The script uses `target\release\rshim.exe` relative to its own location. It
updates executables with a matching `.shim` file in the user and global Scoop
directories, and returns a failure code if a copy fails. Updating global shims
may require an administrator terminal.

## Shim files and behavior

Place a UTF-8 file (with or without a BOM) beside the shim executable, with the
same base name and a `.shim` extension:

```ini
path = "%LOCALAPPDATA%\Programs\example\example.exe"
args = --config "%~dp0\example.json" ""
EXAMPLE_HOME = %USERPROFILE%\example
```

- Preset arguments and the caller's original Windows command line retain their
  quoting, empty arguments, backslashes, and UTF-16 characters.
- `%NAME%` in `path` and environment entries expands against the inherited
  environment. Unknown names stay literal. An empty environment entry removes
  the variable. Environment value quotes are literal.
- Each `%~dp0` in `args` expands to the shim directory, without a trailing slash.
- Console targets inherit input/output and receive Ctrl+C directly. The shim
  waits and returns the target's exit code. Batch targets run through `cmd.exe`.
- GUI targets detach and the shim returns immediately, so applications such as
  Mp3tag do not hold a PowerShell or Command Prompt session open. Redirected
  streams remain available to the GUI process until it closes them.
- Console targets join a cleanup job before they start. Killing the shim kills
  the direct console child; descendants can outlive it so background launchers
  keep working. Detached GUI targets are not placed in that job and outlive the
  shim.
- Targets requiring elevation use the Unicode Windows shell API. UAC-launched
  processes cannot be started suspended through that API, and Windows may deny
  cleanup-job assignment; a failed assignment produces a diagnostic.

## Development checks

```shell
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check
```

The Windows integration tests compile small probe executables using `rustc`
and keep their fixtures under `target\integration-fixtures`. Installer tests
use isolated Scoop directories; they do not replace installed shims. UAC
interaction is not part of the automated tests. Windows API bindings use
`windows-sys`; the `windows` crate is not required.


## Executable Size
Without `crt-static` enabled: around `200kb`

With `crt-static` enabled: around `300kb`
