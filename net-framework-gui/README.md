# .NET Framework Authentication GUI

Windows Forms applications that provide a user interface for Windows NTLM authentication using the Rust authentication library. This solution is compatible with .NET Framework 2.0 and later versions.

## Project Structure

The solution consists of three main projects:

### 1. Rust9xWindowsAuth - Authentication Library
Core authentication library that provides the interface to the Rust DLL.

**Key Files:**
- `CentralFile.cs` - P/Invoke wrapper for Rust DLL interop
- `AuthManager.cs` - High-level authentication manager with retry logic
- `AuthConfig.cs` - Configuration management and validation
- `App.config` - Application configuration file

### 2. HandlerGui - User Interface
Windows Forms application that provides the user interface for authentication.

**Key Files:**
- `Program.cs` - Application entry point and initialization
- `LaunchingForm.cs` - Main launcher form
- `InstallingForm.cs` - Installation progress form
- `ConfirmForm.cs` - Confirmation dialog form
- `AnimatedTransferLine.cs` - Custom UI animation component

### 3. BuildCopyTool - Build Automation
Console application that automates the copying of compiled Rust DLLs to .NET output directories.

**Key Files:**
- `Program.cs` - Build automation logic

## Components

### Rust9xWindowsAuth Project

#### CentralFile.cs - P/Invoke Interop Layer
This is the central interop file that enables .NET applications to use the Rust authentication library. It provides robust DLL loading, function pointer resolution, and memory management.

**Key Features:**
- **Robust DLL Loading**: Multiple search path fallbacks (app directory, assembly location, system PATH)
- **Architecture Detection**: Detects and reports architecture mismatches
- **Function Pointer Resolution**: Dynamic function pointer resolution via `GetProcAddress`
- **Memory Management**: Proper marshaling between managed and unmanaged code
- **Error Handling**: Custom `DllLoadException` and comprehensive error reporting
- **Resource Cleanup**: `AuthResult` class implements `IDisposable` for automatic cleanup

**Key Classes:**
- `WindowsAuth` - Static class containing all P/Invoke methods
- `AuthErrorCode` - Enum defining standard error codes (Success, InvalidCredentials, NetworkError, etc.)
- `AuthInteropResult` - Struct for interop result data
- `AuthResult` - Managed wrapper with automatic resource cleanup
- `DllLoadException` - Custom exception for DLL loading failures

**Usage Example:**
```csharp
// Initialize DLL and library
WindowsAuth.InitializeDll();
WindowsAuth.auth_init();

// Set credentials programmatically
WindowsAuth.SetCredentials("username", "password", "domain");

// OR prompt for credentials
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

#### AuthManager.cs - High-Level Authentication Manager
Provides a high-level abstraction over the raw P/Invoke calls with built-in retry logic, error handling, and workflow management.

**Key Features:**
- **Automatic Retry Logic**: Configurable retry attempts with delays
- **Credential Management**: Support for pre-configured credentials and auto-prompting
- **Error Classification**: Determines which errors should trigger retries
- **Configuration Integration**: Works with `AuthConfig` for settings management
- **Resource Management**: Implements `IDisposable` for proper cleanup

**Key Methods:**
- `Initialize()` - Initialize the authentication library
- `Authenticate()` - Perform authentication with automatic retry logic
- `PromptForCredentials()` - Show Windows credential dialog
- `UpdateConfig()` - Update configuration at runtime
- `Cleanup()` - Clean up authentication resources

**Authentication Flow:**
1. Check if library is initialized, initialize if needed
2. Set pre-configured credentials if available
3. Auto-prompt for credentials if enabled and no pre-configured credentials
4. Perform HTTP authentication request with retry logic
5. Return result or retry on transient failures

#### AuthConfig.cs - Configuration Management
Manages authentication configuration with support for both app.config and runtime configuration.

**Configuration Options:**
- `AuthUrl` - Target URL for authentication requests
- `HttpMethod` - HTTP method (GET, POST, etc.)
- `RequestBody` - Request body for POST requests
- `TimeoutMs` - Request timeout in milliseconds
- `AutoPromptCredentials` - Whether to automatically prompt for credentials
- `CredentialCaption` - Caption for credential dialog
- `CredentialMessage` - Message for credential dialog
- `AllowSaveCredentials` - Whether to show save credentials option
- `Username/Password/Domain` - Pre-configured credentials
- `MaxRetryAttempts` - Maximum retry attempts for failed authentication
- `RetryDelayMs` - Delay between retry attempts
- `EnableVerboseLogging` - Enable verbose logging
- `LogFilePath` - Path to log file

**Features:**
- **app.config Integration**: Reads settings from application configuration file
- **Validation**: Validates configuration before use
- **Cloning**: Supports configuration cloning for runtime updates
- **Logging**: Built-in logging support with file output

**Example app.config:**
```xml
<configuration>
  <appSettings>
    <add key="AuthUrl" value="https://example.com/api/auth"/>
    <add key="HttpMethod" value="GET"/>
    <add key="TimeoutMs" value="30000"/>
    <add key="AutoPromptCredentials" value="true"/>
    <add key="MaxRetryAttempts" value="3"/>
    <add key="RetryDelayMs" value="1000"/>
    <add key="EnableVerboseLogging" value="true"/>
  </appSettings>
</configuration>
```

### HandlerGui Project

#### Program.cs - Application Entry Point
Main application entry point that initializes the authentication manager and starts the GUI.

**Key Responsibilities:**
- Initialize `AuthManager` with configuration
- Start authentication library
- Launch main form (`LaunchingForm`)
- Handle startup errors gracefully
- Ensure proper cleanup on application exit

**Startup Flow:**
1. Enable Visual Styles and set text rendering defaults
2. Create and configure `AuthManager` instance
3. Initialize authentication library
4. Show error dialog if initialization fails
5. Start `LaunchingForm` as main application form
6. Cleanup authentication resources on exit

#### LaunchingForm.cs - Main Launcher Form
Main application form that serves as the primary user interface for the authentication application.

**Features:**
- Application launching and initialization
- User interface for authentication operations
- Integration with authentication manager
- Error handling and user feedback

#### InstallingForm.cs - Installation Progress Form
Progress form that shows installation or operation progress to the user.

**Features:**
- Progress indication for long-running operations
- Status updates and user feedback
- Cancellation support (if implemented)
- Animated progress indicators

#### ConfirmForm.cs - Confirmation Dialog
Standard confirmation dialog for user decisions.

**Features:**
- Yes/No confirmation dialogs
- Custom messages and captions
- Integration with application workflow
- Consistent UI styling

#### AnimatedTransferLine.cs - Custom UI Component
Custom Windows Forms control that provides animated visual feedback.

**Features:**
- Animated transfer/progress indication
- Custom drawing and animation logic
- Visual feedback for operations
- Reusable component architecture

### BuildCopyTool Project

#### Program.cs - Build Automation Tool
Console application that automates the copying of compiled Rust DLLs to .NET output directories with intelligent path resolution and verification.

**Key Features:**
- **Automatic DLL Detection**: Recursively searches for the most recently compiled Rust DLL by modification time
- **Intelligent Path Resolution**: Walks up directory tree to locate rust-src and project directories
- **Configuration Detection**: Automatically detects Debug/Release configuration from DLL path
- **Recursive Copying**: Copies DLL and all runtime dependencies with depth limiting
- **File Verification**: Verifies copied files by size and timestamp
- **Error Handling**: Comprehensive error handling with detailed console output
- **Build Integration**: Designed for integration with Visual Studio build events

**Detailed Workflow:**

1. **Argument Processing** (Lines 23-45):
   - Accepts 0, 1, 2, or 3 arguments
   - 0 args: Uses current directory as project directory, auto-detects configuration
   - 1 arg: Uses specified directory as project directory, auto-detects configuration
   - 2 args: Uses first as project directory, second as target directory, auto-detects configuration
   - 3 args: Uses first as project directory, second as target directory, third as configuration (Debug/Release)

2. **Path Resolution** (Lines 40-51):
   - Normalizes paths (removes quotes, converts to full paths)
   - Validates that directories exist
   - Provides detailed console output for debugging

3. **rust-src Location** (Lines 53-61, 272-313):
   - Starts from project directory
   - Walks up directory tree (up to 10 levels)
   - Looks for "rust-src" subdirectory at each level
   - Returns full path when found

4. **DLL Search** (Lines 79-100, 328-415):
   - Searches in `rust-src/target` directory
   - Recursively searches subdirectories (max depth 6)
   - Collects all `rust9x_windows_auth.dll` files found
   - **Configuration Filtering**: If configuration is specified, filters DLLs by matching build configuration (Debug/Release)
   - Sorts by modification time (newest first)
   - Displays top 5 candidates with configuration info for verification
   - Selects and returns the most recently modified DLL matching the configuration

5. **Configuration Detection** (Lines 59-74, 102-120, 517-652):
   - **Multiple Detection Methods**:
     - **MSBuild Auto-detection**: Checks bin/Debug, bin/Release, obj/Debug, obj/Release directories for recent activity
     - **Project File Analysis**: Examines .csproj files for default Configuration property
     - **Environment Variables**: Checks Configuration and BuildConfiguration environment variables
     - **DLL Path Analysis**: Checks Rust DLL path for "dll-debug", "dll-release", "debug", "release" indicators
   - **Priority System**: 
     1. Explicitly provided configuration parameter
     2. Auto-detected MSBuild configuration
     3. DLL path-based detection
   - **Verification**: Warns if provided configuration differs from detected configuration
   - **Priority**: Uses provided configuration for output directory, even if DLL detection differs
   - **Result**: Returns "Debug", "Release", or "Unknown"

6. **Output Directory Location** (Lines 126-138, 677-776):
   - **Configuration Priority**:
     1. Uses specified configuration directory if provided (bin/Debug or bin/Release)
     2. Auto-detects based on most recent file activity in Debug vs Release directories
     3. Falls back to available Debug or Release directory
   - **Project Search**: Walks up directory tree looking for "HandlerGui" or "Rust9xWindowsAuth" projects
   - **Directory Validation**: Ensures target directories exist and are accessible
   - **Auto-detection Logic**: Compares file modification times to determine most recently used configuration

7. **File Copying** (Lines 106-117, 521-619):
   - Creates destination directory if needed
   - Copies main DLL with verification
   - Recursively copies entire runtime directory
   - Skips .pdb files if configured
   - Verifies each copy by file size and timestamp
   - Provides detailed progress output

**Usage Examples:**
```bash
# Automatic mode (uses current directory, auto-detects MSBuild configuration)
BuildCopyTool.exe

# Specify project directory (auto-detects MSBuild configuration)
BuildCopyTool.exe "E:\code\rust9x-windows2000auth\net-framework-gui\Brutus\HandlerGui"

# Specify both project and target directories (auto-detects MSBuild configuration)
BuildCopyTool.exe "$(ProjectDir)" "$(TargetDir)"

# Specify project, target, and configuration explicitly
BuildCopyTool.exe "$(ProjectDir)" "$(TargetDir)" "Debug"
BuildCopyTool.exe "$(ProjectDir)" "$(TargetDir)" "Release"

# With Visual Studio macros in build events for configuration-aware copying
BuildCopyTool.exe "$(ProjectDir)" "$(TargetDir)" "$(ConfigurationName)"
```

**Build Integration:**
The tool is designed to be called from Visual Studio pre-build or post-build events:
```
BuildCopyTool.exe "$(ProjectDir)" "$(TargetDir)"
```

**Configuration Constants:**
- `DllName = "rust9x_windows_auth.dll"` - Target DLL filename
- `MaxSearchDepth = 6` - Maximum recursive search depth
- `MaxUpwardWalkLevels = 10` - Maximum directory levels to walk up

**Error Codes:**
- 0: Success
- 1: Fatal exception
- 3: Could not locate rust-src directory
- 4: target directory not found
- 5: Could not locate DLL
- 6: Could not locate output directory

## Building the Solution

### Prerequisites
- Visual Studio 2005 or later (for .NET Framework 2.0 compatibility)
- .NET Framework 2.0 or later
- Rust toolchain (for building the authentication DLL)

### Build Steps

1. **Build Rust Authentication Library**
   - Follow instructions in `rust-src/README.md`
   - Build the DLL using appropriate configuration
   - The BuildCopyTool will automatically copy the compiled DLL

2. **Build .NET Solution**
   ```bash
   cd net-framework-gui/Brutus
   msbuild Brutus.sln /p:Configuration=Release
   ```

3. **Configure Build Events** (if needed)
   - Add BuildCopyTool to pre-build or post-build events
   - Ensure proper path references for your development environment

### Output Structure
After building, the output structure will be:
```
net-framework-gui/Brutus/
├── HandlerGui/bin/Release/
│   ├── HandlerGui.exe
│   ├── rust9x_windows_auth.dll
│   └── [runtime dependencies]
├── Rust9xWindowsAuth/bin/Release/
│   ├── Rust9xWindowsAuth.dll
│   ├── rust9x_windows_auth.dll
│   └── [runtime dependencies]
└── BuildCopyTool/bin/Release/
    └── BuildCopyTool.exe
```

## Configuration

### Application Configuration
Configure authentication settings through `App.config` files in each project:

**HandlerGui/App.config:**
```xml
<configuration>
  <appSettings>
    <add key="AuthUrl" value="https://your-server.com/api/auth"/>
    <add key="HttpMethod" value="GET"/>
    <add key="AutoPromptCredentials" value="true"/>
    <add key="CredentialCaption" value="Authentication Required"/>
    <add key="CredentialMessage" value="Enter your Windows credentials"/>
    <add key="MaxRetryAttempts" value="3"/>
    <add key="RetryDelayMs" value="1000"/>
    <add key="EnableVerboseLogging" value="true"/>
  </appSettings>
</configuration>
```

### Runtime Configuration
Configuration can also be modified programmatically:
```csharp
AuthConfig config = AuthConfig.Current;
config.AuthUrl = "https://new-server.com/api";
config.MaxRetryAttempts = 5;
authManager.UpdateConfig(config);
```

## Deployment

### Deployment Requirements
1. **.NET Framework**: Target system must have .NET Framework 2.0 or later
2. **Rust DLL**: `rust9x_windows_auth.dll` must be in application directory
3. **Runtime Dependencies**: All required runtime files must be included
4. **Configuration**: App.config properly configured for target environment

### Deployment Steps
1. Build solution in Release configuration
2. Use BuildCopyTool to ensure latest DLL is copied
3. Package application files and dependencies
4. Deploy to target system
5. Configure App.config for production environment
6. Test authentication with target server

## Troubleshooting

### Common Issues

**DLL Loading Failures:**
- Ensure `rust9x_windows_auth.dll` is in application directory
- Check architecture compatibility (32-bit vs 64-bit)
- Verify all runtime dependencies are present
- Use `WindowsAuth.IsDllLoaded` to check DLL status

**Authentication Failures:**
- Enable verbose logging to diagnose issues
- Check network connectivity to auth server
- Verify credentials are correct
- Review server logs for authentication attempts

**Build Issues:**
- Ensure Rust DLL is built before .NET solution
- Check BuildCopyTool output for DLL copying issues
- Verify path references in build events
- Check Visual Studio build output for errors

### Logging
Enable verbose logging to troubleshoot issues:
```xml
<add key="EnableVerboseLogging" value="true"/>
<add key="LogFilePath" value="C:\temp\auth.log"/>
```

Logs will include:
- DLL loading and initialization
- Authentication attempts and results
- HTTP request/response details
- Error messages and stack traces

## Development

### Adding New Forms
1. Create new Windows Form in HandlerGui project
2. Add necessary UI components
3. Integrate with `AuthManager` for authentication
4. Update `Program.cs` if needed for startup flow

### Extending Authentication
1. Add new methods to `AuthManager.cs`
2. Update `AuthConfig.cs` for new configuration options
3. Extend `CentralFile.cs` if new P/Invoke functions are needed
4. Update Rust library accordingly

### Build Process Customization
1. Modify `BuildCopyTool.csproj` for additional build steps
2. Update `Program.cs` in BuildCopyTool for custom copy logic
3. Add Visual Studio build events as needed
4. Test build process in both Debug and Release configurations

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    HandlerGui.exe                           │
│              (Windows Forms Application)                      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  LaunchingForm.cs - Main UI Form                       │  │
│  │  InstallingForm.cs - Progress Form                     │  │
│  │  ConfirmForm.cs - Confirmation Dialog                  │  │
│  │  AnimatedTransferLine.cs - Custom Control             │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Rust9xWindowsAuth.dll                       │
│              (.NET Authentication Library)                  │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  AuthManager.cs - High-level authentication logic       │  │
│  │  AuthConfig.cs - Configuration management              │  │
│  │  CentralFile.cs - P/Invoke interop layer               │  │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ P/Invoke
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              rust9x_windows_auth.dll (Rust)                 │
│              (Native Authentication Library)               │
└─────────────────────────────────────────────────────────────┘
```

## Compatibility

- **.NET Framework**: 2.0 and later
- **Windows Versions**: Windows 2000, XP, Vista, 7, 8, 10, 11
- **Architecture**: Primarily 32-bit (x86) for legacy compatibility
- **Visual Studio**: 2005 and later

## Security Considerations

- Credentials are handled securely using Windows credential APIs
- Configuration files should not contain production passwords
- Use Windows authentication where possible
- Enable TLS for production environments
- Implement proper error handling to avoid information disclosure
- Log files may contain sensitive information - secure appropriately