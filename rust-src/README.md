# rust9x Windows Authentication DLL

Windows Authentication library for legacy Windows systems (Windows 2000, XP, 9x/ME) using rust9x. Provides NTLM authentication, TLS support, and Windows credential dialog integration for .NET Framework 2.0 applications.

## Features

- **NTLMv2 Authentication**: Pure Rust implementation using sspi-rs, compatible with legacy Windows
- **TLS/HTTPS Support**: native-tls using Windows SChannel for secure connections (Windows 2000+)
- **Windows Credential Dialog**: Native Windows credential prompt via CredUIPromptForCredentials
- **HTTP Client**: Built-in HTTP client with automatic NTLM authentication flow
- **.NET Interop**: C-compatible API for P/Invoke from .NET Framework 2.0
- **Dual Build**: Can be built as both DLL (for .NET) and standalone EXE (for testing)

## Architecture

```
.NET Framework 2.0 App
         ↓ P/Invoke
rust9x_windows_auth.dll (Rust)
         ↓
┌─────────────────────────────┐
│  NTLM Authentication (sspi) │
│  TLS/HTTPS (rustls)         │
│  Windows API (CredUI)       │
│  HTTP Client                │
└─────────────────────────────┘
         ↓
ASP.NET Core API Server (Modern System)
```

## Building

### Prerequisites

1. **rust9x toolchain**: Install and link the rust9x toolchain
2. **Platform SDK**: Update paths in `.cargo/config.toml` to match your setup
3. **For Windows 9x/ME**: Place `unicows.dll` alongside the DLL

### Build Commands

```bash
# Build DLL for .NET interop (release, static CRT - no MSVCR dependency on target)
# NOTE: This builds ONLY the DLL, not the test EXE
cargo +rust9x dll-release

# Build DLL for .NET interop (debug, static CRT - no MSVCR dependency on target)
# NOTE: This builds ONLY the DLL, not the test EXE
cargo +rust9x dll-debug

# Build test harness EXE (release, dynamic CRT - requires MSVCR on target)
cargo +rust9x exe-release

# Build test harness EXE (debug, dynamic CRT - requires MSVCR on target)
cargo +rust9x exe-debug

# Build test harness EXE (release, static CRT - no MSVCR dependency on target)
cargo +rust9x exe-static-release

# Build test harness EXE (debug, static CRT - no MSVCR dependency on target)
cargo +rust9x exe-static-debug
```

Or use the full cargo commands:

```bash
# Build DLL for .NET interop (release, static CRT - no MSVCR dependency on target)
# NOTE: This builds ONLY the DLL, not the test EXE
cargo +rust9x build --target i686-rust9x-windows-msvc --release --lib --features "std,network,tls,dll-build"

# Build DLL for .NET interop (debug, static CRT - no MSVCR dependency on target)
# NOTE: This builds ONLY the DLL, not the test EXE
cargo +rust9x build --target i686-rust9x-windows-msvc --lib --features "std,network,tls,dll-build"

# Build DLL for legacy systems (no_std, release, static CRT)
# NOTE: This builds ONLY the DLL, not the test EXE
cargo +rust9x build --target i686-rust9x-windows-msvc --release --lib --features "network,tls,dll-build"

# Build test harness EXE (release, dynamic CRT - requires MSVCR on target)
cargo +rust9x build --target i686-rust9x-windows-msvc --bin rust9x_auth_test --release --features "std,network,tls,exe-build"

# Build test harness EXE (debug, dynamic CRT - requires MSVCR on target)
cargo +rust9x build --target i686-rust9x-windows-msvc --bin rust9x_auth_test --features "std,network,tls,exe-build"

# Build test harness EXE (release, static CRT - no MSVCR dependency on target)
cargo +rust9x build --target i686-rust9x-windows-msvc --bin rust9x_auth_test --release --features "std,network,tls,exe-static-build"

# Build test harness EXE (debug, static CRT - no MSVCR dependency on target)
cargo +rust9x build --target i686-rust9x-windows-msvc --bin rust9x_auth_test --features "std,network,tls,exe-static-build"
```

### Output Files

Each build variant outputs to a separate directory:

- `target/dll-release/i686-rust9x-windows-msvc/release/rust9x_windows_auth.dll` - DLL (release, static CRT)
- `target/dll-debug/i686-rust9x-windows-msvc/debug/rust9x_windows_auth.dll` - DLL (debug, static CRT)
- `target/exe-release/i686-rust9x-windows-msvc/release/rust9x_auth_test.exe` - EXE (release, dynamic CRT)
- `target/exe-debug/i686-rust9x-windows-msvc/debug/rust9x_auth_test.exe` - EXE (debug, dynamic CRT)
- `target/exe-static-release/i686-rust9x-windows-msvc/release/rust9x_auth_test.exe` - EXE (release, static CRT)
- `target/exe-static-debug/i686-rust9x-windows-msvc/debug/rust9x_auth_test.exe` - EXE (debug, static CRT)

Each output directory also includes:
- `Microsoft.VC80.CRT/msvcr80.dll` - Visual C++ 2005 runtime (SxS assembly)
- `Microsoft.VC80.CRT/Microsoft.VC80.CRT.manifest` - Assembly manifest
- `msvcr80.dll` - Flat layout fallback for XP and below
- `msvcr80.dll.manifest` - DLL manifest for flat layout

## .NET Framework 2.0 Integration

See `NET_INTEROP.cs` for complete C# P/Invoke declarations and usage example.

## Legacy Windows Compatibility

| Windows Version | NTLM | TLS | Notes |
|----------------|------|-----|-------|
| Windows 95/98/ME | ✓ | ✗ | Requires unicows.dll |
| Windows NT 4.0 | ✓ | ✗ | No TLS support |
| Windows 2000 | ✓ | ✓ | Full support |
| Windows XP | ✓ | ✓ | Full support |
| Windows Vista+ | ✓ | ✓ | Full support |

## Credits

- **rust9x**: https://github.com/rust9x/rust - Rust for legacy Windows
- **sspi-rs**: https://github.com/Devolutions/sspi-rs - SSPI implementation
- **rustls**: https://github.com/rustls/rustls - TLS library
