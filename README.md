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
# Build DLL for .NET interop (with std for development)
cargo +rust9x build --target i686-rust9x-windows-msvc --release --features "std,network,tls"

# Build DLL for legacy systems (no_std)
cargo +rust9x build --target i686-rust9x-windows-msvc --release --features "network,tls"

# Build test harness EXE
cargo +rust9x build --target i686-rust9x-windows-msvc --bin rust9x_auth_test --release --features "std,network,tls"
```

### Output Files

- `target/i686-rust9x-windows-msvc/release/rust9x_windows_auth.dll` - Main DLL for .NET
- `target/i686-rust9x-windows-msvc/release/rust9x_auth_test.exe` - Test harness

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
