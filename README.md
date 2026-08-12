# Rust9x Windows Authentication Library

A cross-platform Windows NTLM authentication library that combines Rust's performance and security with .NET Framework's ease of use. This project provides a robust solution for Windows authentication on legacy systems (Windows 9x/ME) and modern Windows platforms.

## Project Structure

The project consists of two main components:

### `rust-src/` - Rust Authentication Library
A native Rust library that implements Windows NTLM authentication using the Security Support Provider Interface (SSPI). This library compiles to a DLL that can be called from .NET applications.

**Key Files:**
- `src/lib.rs` - Main library entry point with C interop functions
- `src/auth.rs` - Core NTLM authentication implementation using SSPI
- `src/http.rs` - HTTP client with integrated NTLM authentication
- `src/tls.rs` - TLS configuration for HTTPS connections
- `src/main.rs` - Test harness for Rust stdlib compatibility testing
- `Cargo.toml` - Rust project configuration

### `net-framework-gui/` - .NET Framework GUI Applications
Windows Forms applications that provide a user interface for authentication and consume the Rust authentication library.

**Key Files:**
- `Brutus/Rust9xWindowsAuth/CentralFile.cs` - P/Invoke wrapper for Rust DLL interop
- `Brutus/HandlerGui/` - GUI forms for credential dialogs and authentication UI

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    .NET Application                         │
│              (Windows Forms / Console)                      │
└──────────────────────────┬──────────────────────────────────┘
                           │ P/Invoke calls
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              CentralFile.cs (.NET Interop Layer)             │
│  - DLL loading and management                               │
│  - Function pointer resolution                              │
│  - Memory management for interop                            │
│  - Error handling and logging                               │
└──────────────────────────┬──────────────────────────────────┘
                           │ C FFI boundary
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              rust9x_windows_auth.dll (Rust)                  │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ lib.rs - C Interop Layer                              │  │
│  │ - auth_init() / auth_cleanup()                        │  │
│  │ - auth_set_credentials()                              │  │
│  │ - auth_http_request()                                 │  │
│  │ - auth_prompt_credentials()                           │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │                                │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │ auth.rs - NTLM Authentication Engine                  │  │
│  │ - WindowsAuthClient struct                           │  │
│  │ - generate_negotiate_token() (Type 1 message)        │  │
│  │ - process_challenge() (Type 3 message)                │  │
│  │ - Windows credential dialog integration              │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │                                │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │ http.rs - HTTP Client with NTLM                       │  │
│  │ - HTTP request/response handling                     │  │
│  │ - NTLM challenge-response protocol                    │  │
│  │ - Base64 encoding/decoding                            │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │                                │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │ tls.rs - TLS/SSL Support                             │  │
│  │ - TlsConfig for HTTPS connections                    │  │
│  │ - Certificate verification control                    │  │
│  └──────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ Windows SSPI
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Windows Security Subsystem                      │
│  - Security Support Provider Interface (SSPI)               │
│  - Credential Manager                                      │
│  - Windows Credential UI                                   │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Rust Authentication Library (`rust-src/`)

#### `src/lib.rs` - C Interop Layer
This file provides the C-compatible interface that .NET applications can call via P/Invoke. It handles:

- **Memory Management**: Conversion between Rust and C memory representations
- **Error Handling**: Translation between Rust `Result` types and C error codes
- **Global State**: Manages the global `AUTH_CLIENT` instance
- **String Marshaling**: Safe conversion between C strings and Rust strings

**Key Functions:**
- `auth_init()` - Initialize the authentication library
- `auth_cleanup()` - Free library resources
- `auth_set_credentials()` - Set authentication credentials programmatically
- `auth_http_request()` - Perform HTTP request with NTLM authentication
- `auth_prompt_credentials()` - Show Windows credential dialog

#### `src/auth.rs` - NTLM Authentication Engine
Implements the core NTLM authentication protocol using Windows SSPI:

- **WindowsAuthClient**: Main authentication client structure
- **NTLM Protocol Implementation**:
  - `generate_negotiate_token()`: Generates Type 1 NTLM negotiate message
  - `process_challenge()`: Processes Type 2 challenge and generates Type 3 authenticate message
- **SSPI Integration**: Uses the `sspi` crate for Windows security functions
- **Credential Dialog**: Windows credential UI integration via `CredUIPromptForCredentialsW`
- **Error Handling**: Comprehensive SSPI error code mapping and logging

**Key Features:**
- Support for both local and domain accounts
- Detailed logging of SSPI API calls and responses
- Windows credential dialog integration for user-friendly authentication
- Proper error handling with descriptive error messages

#### `src/http.rs` - HTTP Client with NTLM
HTTP client that seamlessly integrates NTLM authentication:

- **HTTP Protocol**: Full HTTP/1.1 client implementation
- **NTLM Integration**: Automatic NTLM challenge-response handling
- **TLS Support**: HTTPS connections with configurable certificate verification
- **Base64 Encoding**: Custom Base64 implementation for NTLM token encoding
- **Connection Management**: TCP connection handling with timeouts

**Authentication Flow:**
1. Parse URL and establish TCP connection
2. Generate NTLM negotiate token (Type 1)
3. Send initial HTTP request with `Authorization: NTLM <token>` header
4. Receive 401 response with WWW-Authenticate challenge
5. Process challenge and generate authenticate token (Type 3)
6. Send authenticated request
7. Return final response

#### `src/tls.rs` - TLS Configuration
Manages TLS/SSL configuration for HTTPS connections:

- **TlsConfig**: Configuration structure for TLS settings
- **Certificate Verification**: Control over certificate validation
- **Connector Building**: Creates `native_tls::TlsConnector` instances
- **Security Options**: Support for accepting invalid certificates (development mode)

### 2. .NET Interop Layer (`net-framework-gui/`)

#### `Brutus/Rust9xWindowsAuth/CentralFile.cs`
This is the central interop file that enables .NET applications to use the Rust authentication library:

**Key Features:**

- **Robust DLL Loading**:
  - Multiple search path fallbacks (app directory, assembly location, system PATH)
  - Architecture mismatch detection
  - Detailed error messages for DLL loading failures
  - Explicit DLL handle management via `LoadLibrary`/`FreeLibrary`

- **Function Pointer Resolution**:
  - Dynamic function pointer resolution via `GetProcAddress`
  - Delegate creation for type-safe P/Invoke calls
  - Error checking for missing functions

- **Memory Management**:
  - Proper marshaling of strings and data between managed and unmanaged code
  - `AuthResult` class implements `IDisposable` for automatic cleanup
  - Safe handling of unmanaged memory allocation/deallocation

- **Error Handling**:
  - Custom `DllLoadException` for DLL loading errors
  - `AuthErrorCode` enum for standardized error reporting
  - Comprehensive logging via `Trace.WriteLine`

**Key Classes:**

- `WindowsAuth`: Static class containing all P/Invoke methods
- `AuthErrorCode`: Enum defining standard error codes
- `AuthInteropResult`: Struct for interop result data
- `AuthResult`: Managed wrapper with automatic resource cleanup
- `DllLoadException`: Custom exception for DLL loading failures

**Usage Example:**
```csharp
// Initialize DLL and library
WindowsAuth.InitializeDll();
WindowsAuth.auth_init();

// Set credentials or prompt user
WindowsAuth.SetCredentials("username", "password", "domain");
// OR
using (var result = WindowsAuth.PromptCredentials("Auth Required", "Enter credentials", false))
{
    if (!result.Success) { /* handle error */ }
}

// Make authenticated HTTP request
using (var response = WindowsAuth.HttpRequest("http://example.com/api"))
{
    if (response.Success) {
        Console.WriteLine(response.ResponseString);
    }
}

// Cleanup
WindowsAuth.auth_cleanup();
WindowsAuth.UnloadDll();
```

## Building the Project

### Rust Library

For detailed Rust build instructions, see [`rust-src/README.md`](rust-src/README.md). The Rust library provides multiple build configurations for different scenarios (DLL vs EXE, debug vs release, static vs dynamic CRT).

### .NET Applications

```bash
cd net-framework-gui/Brutus

# Build using MSBuild
msbuild Brutus.sln /p:Configuration=Release

# Or using Visual Studio
# Open Brutus.sln and build in Release mode
```

### Automated DLL Copying

The project includes a `BuildCopyTool` that automatically handles copying the compiled Rust DLL and its dependencies to the appropriate .NET output directories. This tool is integrated into the build process and ensures that the latest compiled DLL is always available to the .NET applications.

For detailed information about the .NET Framework components and build process, see [`net-framework-gui/README.md`](net-framework-gui/README.md).

## Deployment

1. **Rust DLL**: Place `rust9x_windows_auth.dll` in the .NET application directory
2. **Dependencies**: Ensure required Windows libraries are available on target system
3. **Configuration**: Configure TLS settings and authentication parameters as needed

## Features

- **Cross-Platform**: Works on Windows 9x/ME, Windows XP, and modern Windows versions
- **NTLM Authentication**: Full NTLM protocol implementation via Windows SSPI
- **HTTP/HTTPS Support**: Complete HTTP client with TLS support
- **User Integration**: Windows credential dialog for seamless user experience
- **Error Handling**: Comprehensive error reporting and logging
- **Memory Safety**: Rust's memory safety guarantees for authentication logic
- **Performance**: Native performance for authentication operations

## Use Cases

- Legacy Windows system authentication (Windows 9x/ME)
- Enterprise applications requiring NTLM authentication
- Secure HTTP client with Windows authentication
- Custom authentication protocols requiring NTLM
- Systems where .NET's built-in authentication is insufficient

## Logging

The library includes comprehensive logging to help with debugging:

- **Rust logs**: Written to `auth_log.txt`, `http_log.txt`, `tls_log.txt`, `lib_log.txt`
- **.NET logs**: Written via `Trace.WriteLine` for integration with .NET tracing
- **SSPI logs**: Detailed SSPI API call logging with error codes

## Security Considerations

- Credentials are handled securely using Windows credential APIs
- TLS certificate verification can be configured for development vs production
- Memory is properly managed to prevent leaks
- Error messages don't expose sensitive information

## Dependencies

### Rust Dependencies
- `sspi` - Windows SSPI bindings
- `native-tls` - TLS implementation (optional)
- `windows-sys` - Windows API bindings

### .NET Dependencies
- .NET Framework 2.0 or later
- Windows API (kernel32.dll for DLL loading)

## License

See LICENSE-APACHE and LICENSE-MIT files for details.

## Contributing

This project is designed for compatibility with legacy Windows systems. When contributing, ensure:
- No dependencies on modern Windows features unavailable on Windows 9x/ME
- Proper error handling for all Windows API calls
- Memory safety is maintained
- Cross-version compatibility is tested