# buac

[![Crates.io](https://img.shields.io/crates/v/buac.svg)](https://crates.io/crates/buac)
[![Docs.rs](https://docs.rs/buac/badge.svg)](https://docs.rs/buac)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A minimal, robust, and zero-allocation Windows UAC (User Account Control) elevation library for Rust.

`buac` leverages the COM elevation moniker (`ICMLuaUtil::ShellExec`) combined with dynamic, scoped PEB (Process Environment Block) masquerading to silently elevate privileges or execute processes with Administrator rights on Windows without triggering UAC consent dialogs.

---

## Features

- **Zero Runtime Allocations for Masquerading**: PEB strings and moniker GUID strings are stored in static `.rdata`.
- **Automatic PEB Rollback**: Utilizes RAII guards to restore the host process's original PEB structures (`ImagePathName`, `CommandLine`, `FullDllName`, `BaseDllName`) immediately after elevation.
- **Fail-Fast & Strongly Typed Errors**: No silent error suppression. Every step (COM initialization, PEB locking, moniker activation, execution) returns clear `Result<T, Error>` with exact Windows `HRESULT` / Win32 error codes.
- **Windows Command-Line Escaping**: Robustly handles command-line arguments containing spaces, embedded quotes, and backslashes according to Microsoft CRT / `CommandLineToArgvW` standards.
- **Full Architecture Support**: Native support for both `x86_64` and `x86` Windows targets.
- **Thread-Safe by Design**: Internal raw-pointer guards automatically enforce `!Send` and `!Sync`.

---

## Installation

Add `buac` to your `Cargo.toml`:

```toml
[dependencies]
buac = "0.1.1"
```

---

## Usage

### 1. One-Line Self-Elevation

Automatically restarts the current process with elevated privileges if it is not already running as Administrator:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Elevates and terminates the non-elevated parent process.
    // If already elevated, this is a no-op and returns Ok(()).
    buac::elevate()?;

    println!("[+] Running with Administrator privileges!");
    Ok(())
}
```

---

### 2. Mutex-Safe Elevation (Granular Lifecycle Control)

If your application uses single-instance mutexes, named pipes, or file locks, use `spawn_elevated` to perform cleanup before exiting:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Spawns the elevated child without calling std::process::exit(0)
    if buac::spawn_elevated()? {
        // Perform cleanup (drop mutexes, flush logs, close handles)
        println!("[*] Elevated instance spawned, exiting parent cleanly.");
        return Ok(());
    }

    // Execution continues here only in the elevated process
    println!("[+] Running elevated!");
    Ok(())
}
```

---

### 3. Check Privilege Status

Check whether the current token is elevated:

```rust
if buac::is_elevated()? {
    println!("Process is elevated");
} else {
    println!("Process is not elevated");
}
```

---

### 4. Execute an Arbitrary Process with Elevation

Execute any target binary as Administrator:

```rust
buac::execute("C:\\Windows\\System32\\cmd.exe", Some("/k whoami /priv"))?;
```

---

## How It Works

1. **PEB Masquerading**: The library acquires the PEB lock via `ntdll!RtlAcquirePebLock` and temporarily swaps `ProcessParameters` and `InLoadOrderModuleList` entries to point to `C:\Windows\explorer.exe`.
2. **COM Elevation Moniker**: Activates the elevated `CMSTPLUA` COM object (`{3E5FC7F9-9A51-4367-9063-A120244FBEC7}`) implementing `ICMLuaUtil`. Windows AppInfo validates the caller against the masqueraded PEB and grants auto-elevation.
3. **Execution**: Invokes `ICMLuaUtil::ShellExec` with the target binary and parameters.
4. **RAII Cleanup**: Restores original PEB structures and releases COM interfaces, apartments, and kernel locks safely.

---

## Disclaimer

This library is intended for educational, research, and legitimate administrative automation purposes. Use responsibly in accordance with applicable laws and security policies.

---

## License

Licensed under the [MIT License](LICENSE).
