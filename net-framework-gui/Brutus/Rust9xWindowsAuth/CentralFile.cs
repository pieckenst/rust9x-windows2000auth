// .NET Framework 2.0+ P/Invoke declarations for rust9x_windows_auth.dll
// This file shows how to call the Rust DLL from C# / VB.NET
// Compatible with .NET Framework 2.0 and later versions
//
// ROBUST DLL LOADING:
// This implementation uses explicit DLL loading via LoadLibrary to provide:
// - Better error messages when DLL loading fails
// - Multiple search path fallbacks (app directory, assembly location, system PATH)
// - Architecture mismatch detection
// - Proper DLL handle management
// - Function pointer resolution with error checking
//
// USAGE:
// 1. Call WindowsAuth.InitializeDll() before any other operations
// 2. Use the helper methods (SetCredentials, HttpRequest, etc.) which handle errors gracefully
// 3. Call WindowsAuth.auth_cleanup() when done with the library
// 4. Call WindowsAuth.UnloadDll() to explicitly unload the DLL (optional but recommended)
//
// DLL SEARCH ORDER:
// 1. Application directory (AppDomain.CurrentDomain.BaseDirectory)
// 2. Assembly location (same directory as the calling assembly)
// 3. Current working directory
// 4. "rust-runtime" subdirectory of application directory
// 5. Parent directory (for development scenarios)
// 6. System PATH (handled by LoadLibrary)
//
// ERROR HANDLING:
// - DllLoadException is thrown when DLL loading fails with detailed error messages
// - InvalidOperationException is thrown when functions fail due to DLL loading issues
// - All helper methods wrap native calls with proper exception handling

using System;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;
using System.Reflection;
using System.Diagnostics;

namespace Rust9xWindowsAuth
{
    /// <summary>
    /// Error codes returned by the Rust authentication library
    /// </summary>
    public enum AuthErrorCode
    {
        Success = 0,
        InvalidCredentials = 1,
        NetworkError = 2,
        TlsError = 3,
        AuthFailed = 4,
        InvalidParameter = 5,
        NotInitialized = 6,
        Unknown = -1
    }

    /// <summary>
    /// Result structure for authentication operations
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct AuthInteropResult
    {
        public AuthErrorCode error_code;
        public IntPtr error_message;
        public IntPtr response_data;
        public UIntPtr response_length;
    }

    /// <summary>
    /// Exception thrown when DLL loading fails
    /// </summary>
    public class DllLoadException : Exception
    {
        public DllLoadException(string message) : base(message) { }
        public DllLoadException(string message, Exception innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// P/Invoke wrapper for rust9x_windows_auth.dll with robust DLL loading
    /// </summary>
    public static class WindowsAuth
    {
        private const string DLL_NAME = "rust9x_windows_auth.dll";
        private static IntPtr _dllHandle = IntPtr.Zero;
        private static bool _isInitialized = false;
        private static readonly object _initLock = new object();

        #region Windows API for DLL Loading

        [DllImport("kernel32.dll",
    EntryPoint = "LoadLibraryA",
    ExactSpelling = true,
    SetLastError = true)]
        private static extern IntPtr LoadLibrary(
            [MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll",
            EntryPoint = "FreeLibrary",
            ExactSpelling = true,
            SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr hModule);

        [DllImport("kernel32.dll",
            EntryPoint = "GetProcAddress",
            ExactSpelling = true,
            SetLastError = true)]
        private static extern IntPtr GetProcAddress(
            IntPtr hModule,
            [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

        #endregion

        #region DLL Loading

        /// <summary>
        /// Initialize the DLL and load it explicitly
        /// </summary>
        /// <returns>True if DLL was loaded successfully, false otherwise</returns>
        public static bool InitializeDll()
        {
            try
            {
                lock (_initLock)
                {
                    Trace.WriteLine("InitializeDll: Starting DLL initialization");
                    
                    if (_isInitialized && _dllHandle != IntPtr.Zero)
                    {
                        Trace.WriteLine("InitializeDll: DLL already loaded, handle: " + _dllHandle);
                        return true;
                    }

                    Trace.WriteLine("InitializeDll: Searching for DLL: " + DLL_NAME);
                    string dllPath = FindDllPath();
                    
                    if (dllPath == null)
                    {
                        Trace.WriteLine("InitializeDll: DLL not found in any search path");
                        throw new DllLoadException(
                            "Could not find " + DLL_NAME + ". " +
                            "Searched in: application directory, assembly location, and system PATH.");
                    }

                    Trace.WriteLine("InitializeDll: Attempting to load DLL from: " + dllPath);
                    _dllHandle = LoadLibrary(dllPath);
                    
                    if (_dllHandle == IntPtr.Zero)
                    {
                        int error = Marshal.GetLastWin32Error();
                        Trace.WriteLine("InitializeDll: LoadLibrary failed with error code: " + error);
                        throw new DllLoadException(
                            "Failed to load DLL from '" + dllPath + "'. Windows error code: " + error + ". " +
                            GetLoadLibraryErrorMessage(error));
                    }

                    _isInitialized = true;
                    Trace.WriteLine("InitializeDll: DLL loaded successfully, handle: " + _dllHandle);
                    return true;
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("InitializeDll: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new DllLoadException("Failed to initialize DLL: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Find the DLL in various locations
        /// </summary>
        private static string FindDllPath()
        {
            try
            {
                Trace.WriteLine("FindDllPath: Starting DLL search");
                
                string[] searchPaths = new string[]
                {
                    // 1. Application directory
                    AppDomain.CurrentDomain.BaseDirectory,
                    
                    // 2. Assembly location (for DLL in same directory as the assembly)
                    Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location),
                    
                    // 3. Current directory
                    Directory.GetCurrentDirectory(),
                    
                    // 4. Relative 'rust-runtime' subdirectory
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rust-runtime"),
                    
                    // 5. Parent directory (for development scenarios)
                    Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory),
                    
                    // 6. System PATH will be searched automatically by LoadLibrary
                    null
                };

                int pathIndex = 0;
                foreach (string basePath in searchPaths)
                {
                    pathIndex++;
                    if (string.IsNullOrEmpty(basePath))
                    {
                        Trace.WriteLine("FindDllPath: Path " + pathIndex + " is null, will search system PATH");
                        continue;
                    }

                    string dllPath = Path.Combine(basePath, DLL_NAME);
                    Trace.WriteLine("FindDllPath: Checking path " + pathIndex + ": " + dllPath);
                    
                    if (File.Exists(dllPath))
                    {
                        Trace.WriteLine("FindDllPath: DLL found at: " + dllPath);
                        return dllPath;
                    }
                }

                Trace.WriteLine("FindDllPath: DLL not found in any search path, will use system PATH");
                // Return null to let LoadLibrary search system PATH
                return null;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("FindDllPath: Exception occurred while searching for DLL: " + ex.Message);
                throw new DllLoadException("Error while searching for DLL: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Get a human-readable error message for LoadLibrary failure
        /// </summary>
        private static string GetLoadLibraryErrorMessage(int errorCode)
        {
            try
            {
                switch (errorCode)
                {
                    case 126:
                        return "The specified module could not be found (missing dependencies or wrong architecture).";
                    case 127:
                        return "The specified procedure could not be found.";
                    case 5:
                        return "Access is denied.";
                    case 1114:
                        return "DLL initialization routine failed.";
                    case 193:
                        return "The DLL is 32-bit and the application is 64-bit (or vice versa). Architecture mismatch.";
                    default:
                        return "Unknown error (code: " + errorCode + ").";
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("GetLoadLibraryErrorMessage: Exception occurred: " + ex.Message);
                return "Error retrieving error message for code " + errorCode + ": " + ex.Message;
            }
        }

        /// <summary>
        /// Check if the DLL is loaded and available
        /// </summary>
        public static bool IsDllLoaded
        {
            get { return _isInitialized && _dllHandle != IntPtr.Zero; }
        }

        /// <summary>
        /// Get the DLL handle (for advanced scenarios)
        /// </summary>
        public static IntPtr DllHandle
        {
            get { return _dllHandle; }
        }

        /// <summary>
        /// Unload the DLL explicitly
        /// </summary>
        public static void UnloadDll()
        {
            try
            {
                lock (_initLock)
                {
                    Trace.WriteLine("UnloadDll: Starting DLL unload");
                    
                    if (_dllHandle != IntPtr.Zero)
                    {
                        Trace.WriteLine("UnloadDll: Freeing DLL handle: " + _dllHandle);
                        bool result = FreeLibrary(_dllHandle);
                        Trace.WriteLine("UnloadDll: FreeLibrary result: " + result);
                        
                        _dllHandle = IntPtr.Zero;
                        _isInitialized = false;
                        Trace.WriteLine("UnloadDll: DLL unloaded successfully");
                    }
                    else
                    {
                        Trace.WriteLine("UnloadDll: DLL handle is already zero, nothing to unload");
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("UnloadDll: Exception occurred: " + ex.Message);
                throw new InvalidOperationException("Failed to unload DLL: " + ex.Message, ex);
            }
        }

        #endregion

        #region DLL Imports with Robust Loading

        /// <summary>
        /// Helper method to ensure DLL is loaded before calling any function
        /// </summary>
        private static void EnsureDllLoaded()
        {
            try
            {
                if (!_isInitialized)
                {
                    Trace.WriteLine("EnsureDllLoaded: DLL not initialized, calling InitializeDll");
                    InitializeDll();
                }
                else
                {
                    Trace.WriteLine("EnsureDllLoaded: DLL already initialized");
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("EnsureDllLoaded: Exception occurred: " + ex.Message);
                throw new InvalidOperationException("Failed to ensure DLL is loaded: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Initialize the authentication library
        /// Must be called before any other operations
        /// </summary>
        public static AuthErrorCode auth_init()
        {
            try
            {
                Trace.WriteLine("auth_init: Starting initialization");
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_init");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_init: Could not find 'auth_init' function in DLL");
                    throw new DllLoadException("Could not find 'auth_init' function in DLL");
                }

                Trace.WriteLine("auth_init: Found function pointer for auth_init");
                auth_init_delegate del = (auth_init_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_init_delegate));
                
                AuthErrorCode result = del();
                Trace.WriteLine("auth_init: Initialization completed with result: " + result);
                return result;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("auth_init: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to initialize authentication library: " + ex.Message, ex);
            }
        }

        private delegate AuthErrorCode auth_init_delegate();

        /// <summary>
        /// Cleanup and free resources
        /// Should be called when done using the library
        /// </summary>
        public static void auth_cleanup()
        {
            try
            {
                Trace.WriteLine("auth_cleanup: Starting cleanup");
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_cleanup");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_cleanup: Could not find 'auth_cleanup' function in DLL");
                    throw new DllLoadException("Could not find 'auth_cleanup' function in DLL");
                }

                Trace.WriteLine("auth_cleanup: Found function pointer for auth_cleanup");
                auth_cleanup_delegate del = (auth_cleanup_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_cleanup_delegate));
                
                del();
                Trace.WriteLine("auth_cleanup: Cleanup completed");
            }
            catch (Exception ex)
            {
                Trace.WriteLine("auth_cleanup: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to cleanup authentication library: " + ex.Message, ex);
            }
        }

        private delegate void auth_cleanup_delegate();

        /// <summary>
        /// Free a string allocated by Rust
        /// Used to free error messages returned by the library
        /// </summary>
        public static void auth_free_string(IntPtr ptr)
        {
            try
            {
                Trace.WriteLine("auth_free_string: Freeing string at pointer: " + ptr);
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_free_string");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_free_string: Could not find 'auth_free_string' function in DLL");
                    throw new DllLoadException("Could not find 'auth_free_string' function in DLL");
                }

                Trace.WriteLine("auth_free_string: Found function pointer for auth_free_string");
                auth_free_string_delegate del = (auth_free_string_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_free_string_delegate));
                
                del(ptr);
                Trace.WriteLine("auth_free_string: String freed successfully");
            }
            catch (Exception ex)
            {
                Trace.WriteLine("auth_free_string: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to free string: " + ex.Message, ex);
            }
        }

        private delegate void auth_free_string_delegate(IntPtr ptr);

        /// <summary>
        /// Free response data allocated by Rust
        /// Used to free HTTP response data
        /// </summary>
        public static void auth_free_data(IntPtr ptr, UIntPtr length)
        {
            try
            {
                Trace.WriteLine("auth_free_data: Freeing data at pointer: " + ptr + ", length: " + length);
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_free_data");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_free_data: Could not find 'auth_free_data' function in DLL");
                    throw new DllLoadException("Could not find 'auth_free_data' function in DLL");
                }

                Trace.WriteLine("auth_free_data: Found function pointer for auth_free_data");
                auth_free_data_delegate del = (auth_free_data_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_free_data_delegate));
                
                del(ptr, length);
                Trace.WriteLine("auth_free_data: Data freed successfully");
            }
            catch (Exception ex)
            {
                Trace.WriteLine("auth_free_data: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to free data: " + ex.Message, ex);
            }
        }

        private delegate void auth_free_data_delegate(IntPtr ptr, UIntPtr length);

        /// <summary>
        /// Set credentials for authentication programmatically
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="password">Password</param>
        /// <param name="domain">Domain (can be null or empty for local account)</param>
        /// <returns>Error code indicating success or failure</returns>
        public static AuthErrorCode auth_set_credentials(
            string username,
            string password,
            string domain)
        {
            try
            {
                Trace.WriteLine("auth_set_credentials: Setting credentials for user: " + username + ", domain: " + (domain ?? "(null)"));
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_set_credentials");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_set_credentials: Could not find 'auth_set_credentials' function in DLL");
                    throw new DllLoadException("Could not find 'auth_set_credentials' function in DLL");
                }

                Trace.WriteLine("auth_set_credentials: Found function pointer for auth_set_credentials");
                auth_set_credentials_delegate del = (auth_set_credentials_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_set_credentials_delegate));
                
                AuthErrorCode result = del(username, password, domain);
                Trace.WriteLine("auth_set_credentials: Credentials set with result: " + result);
                return result;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("auth_set_credentials: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to set credentials: " + ex.Message, ex);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private delegate AuthErrorCode auth_set_credentials_delegate(
            string username,
            string password,
            string domain);

        /// <summary>
        /// Perform HTTP request with Windows NTLM Authentication
        /// </summary>
        /// <param name="url">Target URL (http:// or https://)</param>
        /// <param name="method">HTTP method (GET, POST, etc.)</param>
        /// <param name="bodyData">Request body data (null for no body)</param>
        /// <param name="bodyLength">Length of request body in bytes</param>
        /// <returns>Result structure containing response data or error information</returns>
        public static AuthInteropResult auth_http_request(
            string url,
            string method,
            IntPtr bodyData,
            UIntPtr bodyLength)
        {
            try
            {
                Trace.WriteLine("auth_http_request: Starting HTTP request to: " + url + ", method: " + method + ", body length: " + bodyLength);
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_http_request");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_http_request: Could not find 'auth_http_request' function in DLL");
                    throw new DllLoadException("Could not find 'auth_http_request' function in DLL");
                }

                Trace.WriteLine("auth_http_request: Found function pointer for auth_http_request");
                auth_http_request_delegate del = (auth_http_request_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_http_request_delegate));
                
                AuthInteropResult result;
                del(url, method, bodyData, bodyLength, out result);
                Trace.WriteLine("auth_http_request: HTTP request completed with error code: " + result.error_code);
                return result;
            }
            catch (Exception ex)
            {
                Trace.WriteLine("auth_http_request: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to perform HTTP request: " + ex.Message, ex);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private delegate void auth_http_request_delegate(
            string url,
            string method,
            IntPtr bodyData,
            UIntPtr bodyLength,
            out AuthInteropResult result);

        /// <summary>
        /// Prompt for credentials using Windows credential dialog
        /// </summary>
        /// <param name="caption">Dialog caption/title</param>
        /// <param name="message">Dialog message/instructions</param>
        /// <param name="saveCredentials">Reference to int for save checkbox state (0 = false, 1 = true)</param>
        /// <param name="result">Output parameter for the result structure</param>
        public static void auth_prompt_credentials(
            string caption,
            string message,
            ref int saveCredentials,
            out AuthInteropResult result)
        {
            result = new AuthInteropResult(); // Initialize to default
            
            try
            {
                Trace.WriteLine(string.Format("auth_prompt_credentials: Prompting for credentials with caption: {0}, save: {1}", 
                    caption ?? "(null)", saveCredentials));
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_prompt_credentials");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_prompt_credentials: Could not find 'auth_prompt_credentials' function in DLL");
                    throw new DllLoadException("Could not find 'auth_prompt_credentials' function in DLL");
                }

                Trace.WriteLine("auth_prompt_credentials: Found function pointer for auth_prompt_credentials");
                auth_prompt_credentials_delegate del = (auth_prompt_credentials_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_prompt_credentials_delegate));
                
                del(caption, message, ref saveCredentials, out result);
                Trace.WriteLine("auth_prompt_credentials: Credential prompt completed with error code: " + result.error_code + ", save: " + saveCredentials);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("EXCEPTION TYPE: " + ex.GetType().FullName);
                Trace.WriteLine("MESSAGE: " + ex.Message);
                Trace.WriteLine("STACK TRACE:\r\n" + ex.StackTrace);
                
                if (ex.InnerException != null)
                {
                    Trace.WriteLine("INNER TYPE: " + ex.InnerException.GetType().FullName);
                    Trace.WriteLine("INNER MESSAGE: " + ex.InnerException.Message);
                    Trace.WriteLine("INNER STACK:\r\n" + ex.InnerException.StackTrace);
                }
                
                Trace.WriteLine("auth_prompt_credentials: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to prompt for credentials: " + ex.Message, ex);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private delegate void auth_prompt_credentials_delegate(
            string caption,
            string message,
            ref int saveCredentials,
            out AuthInteropResult result);

        /// <summary>
        /// Get credentials that were set by credential prompt
        /// </summary>
        /// <param name="username">Output buffer for username (must be pre-allocated)</param>
        /// <param name="usernameLen">Length of username buffer</param>
        /// <param name="password">Output buffer for password (must be pre-allocated)</param>
        /// <param name="passwordLen">Length of password buffer</param>
        /// <param name="domain">Output buffer for domain (must be pre-allocated)</param>
        /// <param name="domainLen">Length of domain buffer</param>
        /// <param name="result">Output parameter for the result structure</param>
        public static void auth_get_credentials(
            StringBuilder username,
            StringBuilder password,
            StringBuilder domain,
            out AuthInteropResult result)
        {
            result = new AuthInteropResult(); // Initialize to default
            
            try
            {
                Trace.WriteLine("auth_get_credentials: Getting credentials from DLL");
                EnsureDllLoaded();
                
                IntPtr funcPtr = GetProcAddress(_dllHandle, "auth_get_credentials");
                if (funcPtr == IntPtr.Zero)
                {
                    Trace.WriteLine("auth_get_credentials: Could not find 'auth_get_credentials' function in DLL");
                    throw new DllLoadException("Could not find 'auth_get_credentials' function in DLL");
                }

                Trace.WriteLine("auth_get_credentials: Found function pointer for auth_get_credentials");
                auth_get_credentials_delegate del = (auth_get_credentials_delegate)Marshal.GetDelegateForFunctionPointer(
                    funcPtr, typeof(auth_get_credentials_delegate));
                
                del(username, username.Capacity, password, password.Capacity, domain, domain.Capacity, out result);
                Trace.WriteLine("auth_get_credentials: Credentials retrieved with error code: " + result.error_code);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("EXCEPTION TYPE: " + ex.GetType().FullName);
                Trace.WriteLine("MESSAGE: " + ex.Message);
                Trace.WriteLine("STACK TRACE:\r\n" + ex.StackTrace);
                
                if (ex.InnerException != null)
                {
                    Trace.WriteLine("INNER TYPE: " + ex.InnerException.GetType().FullName);
                    Trace.WriteLine("INNER MESSAGE: " + ex.InnerException.Message);
                    Trace.WriteLine("INNER STACK:\r\n" + ex.InnerException.StackTrace);
                }
                
                Trace.WriteLine("auth_get_credentials: Exception occurred: " + ex.Message);
                if (ex is DllLoadException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to get credentials: " + ex.Message, ex);
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private delegate void auth_get_credentials_delegate(
            StringBuilder username,
            int usernameLen,
            StringBuilder password,
            int passwordLen,
            StringBuilder domain,
            int domainLen,
            out AuthInteropResult result);

        #endregion

        #region Helper Methods

        /// <summary>
        /// Helper to set credentials programmatically
        /// </summary>
        public static AuthErrorCode SetCredentials(string username, string password, string domain)
        {
            try
            {
                Trace.WriteLine("SetCredentials: Helper method called for user: " + username + ", domain: " + (domain ?? "(null)"));
                try
                {
                    AuthErrorCode result = auth_set_credentials(username, password, domain);
                    Trace.WriteLine("SetCredentials: Credentials set successfully with result: " + result);
                    return result;
                }
                catch (DllLoadException ex)
                {
                    Trace.WriteLine("SetCredentials: DLL loading error: " + ex.Message);
                    throw new InvalidOperationException(
                        "Failed to set credentials due to DLL loading error: " + ex.Message, ex);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("SetCredentials: Exception occurred: " + ex.Message);
                if (ex is InvalidOperationException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to set credentials: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Helper to set credentials for local account (no domain)
        /// </summary>
        public static AuthErrorCode SetCredentials(string username, string password)
        {
            try
            {
                Trace.WriteLine("SetCredentials: Helper method called for local account user: " + username);
                return SetCredentials(username, password, null);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("SetCredentials (local account): Exception occurred: " + ex.Message);
                throw new InvalidOperationException("Failed to set local account credentials: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Helper to perform HTTP GET request
        /// </summary>
        public static AuthResult HttpRequest(string url)
        {
            try
            {
                Trace.WriteLine("HttpRequest: Helper method called for GET request to: " + url);
                return HttpRequest(url, "GET", null);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("HttpRequest (GET): Exception occurred: " + ex.Message);
                throw new InvalidOperationException("Failed to perform HTTP GET request: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Helper to perform HTTP POST request with body
        /// </summary>
        public static AuthResult HttpPost(string url, byte[] body)
        {
            try
            {
                Trace.WriteLine("HttpPost: Helper method called for POST request to: " + url + ", body length: " + (body != null ? body.Length.ToString() : "0"));
                return HttpRequest(url, "POST", body);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("HttpPost: Exception occurred: " + ex.Message);
                throw new InvalidOperationException("Failed to perform HTTP POST request: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Helper to perform HTTP request with method and optional body
        /// </summary>
        public static AuthResult HttpRequest(string url, string method, byte[] body)
        {
            try
            {
                Trace.WriteLine("HttpRequest: Helper method called for " + method + " request to: " + url + ", body length: " + (body != null ? body.Length.ToString() : "0"));
                
                IntPtr bodyPtr = IntPtr.Zero;
                UIntPtr bodyLen = UIntPtr.Zero;

                if (body != null && body.Length > 0)
                {
                    bodyPtr = Marshal.AllocHGlobal(body.Length);
                    Marshal.Copy(body, 0, bodyPtr, body.Length);
                    bodyLen = (UIntPtr)body.Length;
                    Trace.WriteLine("HttpRequest: Allocated unmanaged memory for body at: " + bodyPtr);
                }

                try
                {
                    AuthInteropResult result = auth_http_request(url, method, bodyPtr, bodyLen);
                    Trace.WriteLine("HttpRequest: Request completed successfully");
                    return new AuthResult(result);
                }
                catch (DllLoadException ex)
                {
                    Trace.WriteLine("HttpRequest: DLL loading error: " + ex.Message);
                    throw new InvalidOperationException(
                        "Failed to perform HTTP request due to DLL loading error: " + ex.Message, ex);
                }
                finally
                {
                    if (bodyPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(bodyPtr);
                        Trace.WriteLine("HttpRequest: Freed unmanaged memory for body");
                    }
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("HttpRequest: Exception occurred: " + ex.Message);
                if (ex is InvalidOperationException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to perform HTTP request: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Helper to prompt for credentials using Windows dialog
        /// </summary>
        public static AuthResult PromptCredentials(string caption, string message, bool save)
        {
            try
            {
                Trace.WriteLine("PromptCredentials: Helper method called with caption: " + caption + ", save: " + save);
                try
                {
                    int saveInt = save ? 1 : 0;
                    AuthInteropResult result;
                    auth_prompt_credentials(caption, message, ref saveInt, out result);
                    Trace.WriteLine("PromptCredentials: Credential prompt completed with error code: " + result.error_code + ", save: " + saveInt);
                    return new AuthResult(result);
                }
                catch (DllLoadException ex)
                {
                    Trace.WriteLine("PromptCredentials: DLL loading error: " + ex.Message);
                    throw new InvalidOperationException(
                        "Failed to prompt for credentials due to DLL loading error: " + ex.Message, ex);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine("EXCEPTION TYPE: " + ex.GetType().FullName);
                Trace.WriteLine("MESSAGE: " + ex.Message);
                Trace.WriteLine("STACK TRACE:\r\n" + ex.StackTrace);
                
                if (ex.InnerException != null)
                {
                    Trace.WriteLine("INNER TYPE: " + ex.InnerException.GetType().FullName);
                    Trace.WriteLine("INNER MESSAGE: " + ex.InnerException.Message);
                    Trace.WriteLine("INNER STACK:\r\n" + ex.InnerException.StackTrace);
                }
                
                Trace.WriteLine("PromptCredentials: Exception occurred: " + ex.Message);
                if (ex is InvalidOperationException)
                {
                    throw;
                }
                throw new InvalidOperationException("Failed to prompt for credentials: " + ex.Message, ex);
            }
        }

        /// <summary>
        /// Helper to prompt for credentials with default settings
        /// </summary>
        public static AuthResult PromptCredentials()
        {
            try
            {
                Trace.WriteLine("PromptCredentials: Helper method called with default settings");
                return PromptCredentials(
                    "Windows Authentication",
                    "Enter your credentials to continue",
                    false);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("PromptCredentials (default): Exception occurred: " + ex.Message);
                throw new InvalidOperationException("Failed to prompt for credentials with default settings: " + ex.Message, ex);
            }
        }

        #endregion
    }

    /// <summary>
    /// Wrapper for authentication results with proper disposal
    /// Implements IDisposable to ensure proper cleanup of native resources
    /// </summary>
    public partial class AuthResult : IDisposable
    {
        private AuthInteropResult _result;
        private bool _disposed;
        private AuthErrorCode _directErrorCode;
        private string _directErrorMessage;
        private bool _useDirectValues;

        public AuthResult(AuthInteropResult result)
        {
            Trace.WriteLine("AuthResult: Constructor called");
            Trace.WriteLine("AuthResult: Result error_code: " + result.error_code);
            Trace.WriteLine("AuthResult: Result error_message: " + result.error_message);
            Trace.WriteLine("AuthResult: Result response_data: " + result.response_data);
            Trace.WriteLine("AuthResult: Result response_length: " + result.response_length);
            Trace.WriteLine("AuthResult: _result field assignment");
            _result = result;
            _useDirectValues = false;
            Trace.WriteLine("AuthResult: Constructor completed successfully");
        }

        /// <summary>
        /// Constructor for creating AuthResult with direct error code and message
        /// </summary>
        public AuthResult(AuthErrorCode errorCode, string errorMessage)
        {
            Trace.WriteLine("AuthResult: Direct constructor called with error code: " + errorCode);
            _directErrorCode = errorCode;
            _directErrorMessage = errorMessage;
            _useDirectValues = true;
            _result = new AuthInteropResult();
            Trace.WriteLine("AuthResult: Direct constructor completed successfully");
        }

        /// <summary>
        /// Error code from the operation
        /// </summary>
        public AuthErrorCode ErrorCode
        {
            get 
            { 
                try
                {
                    if (_useDirectValues)
                    {
                        Trace.WriteLine("AuthResult: Getting direct ErrorCode: " + _directErrorCode);
                        return _directErrorCode;
                    }
                    Trace.WriteLine("AuthResult: Getting ErrorCode: " + _result.error_code);
                    return _result.error_code; 
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("AuthResult: Exception occurred while getting ErrorCode: " + ex.Message);
                    return AuthErrorCode.Unknown;
                }
            }
        }

        /// <summary>
        /// Error message (if any), automatically freed on disposal
        /// </summary>
        public string ErrorMessage
        {
            get
            {
                try
                {
                    if (_useDirectValues)
                    {
                        Trace.WriteLine("AuthResult: Getting direct ErrorMessage: " + _directErrorMessage);
                        return _directErrorMessage;
                    }
                    if (_result.error_message != IntPtr.Zero)
                    {
                        string message = Marshal.PtrToStringAnsi(_result.error_message);
                        Trace.WriteLine("AuthResult: Getting ErrorMessage: " + message);
                        return message;
                    }
                    Trace.WriteLine("AuthResult: ErrorMessage is null");
                    return null;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("AuthResult: Exception occurred while getting ErrorMessage: " + ex.Message);
                    return "Error retrieving error message: " + ex.Message;
                }
            }
        }

        /// <summary>
        /// Raw response data bytes (if any), automatically freed on disposal
        /// </summary>
        public byte[] ResponseData
        {
            get
            {
                try
                {
                    if (_result.response_data != IntPtr.Zero && _result.response_length != UIntPtr.Zero)
                    {
                        byte[] data = new byte[(int)_result.response_length];
                        Marshal.Copy(_result.response_data, data, 0, (int)_result.response_length);
                        Trace.WriteLine("AuthResult: Getting ResponseData, length: " + data.Length);
                        return data;
                    }
                    Trace.WriteLine("AuthResult: ResponseData is null");
                    return null;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("AuthResult: Exception occurred while getting ResponseData: " + ex.Message);
                    return null;
                }
            }
        }

        /// <summary>
        /// Response data as UTF-8 string (if any)
        /// </summary>
        public string ResponseString
        {
            get
            {
                try
                {
                    byte[] data = ResponseData;
                    if (data != null)
                    {
                        string response = Encoding.UTF8.GetString(data);
                        Trace.WriteLine("AuthResult: Getting ResponseString, length: " + response.Length);
                        return response;
                    }
                    Trace.WriteLine("AuthResult: ResponseString is null");
                    return null;
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("AuthResult: Exception occurred while getting ResponseString: " + ex.Message);
                    return null;
                }
            }
        }

        /// <summary>
        /// Whether the operation completed successfully
        /// </summary>
        public bool Success
        {
            get 
            { 
                try
                {
                    bool success = _result.error_code == AuthErrorCode.Success;
                    Trace.WriteLine("AuthResult: Getting Success: " + success);
                    return success; 
                }
                catch (Exception ex)
                {
                    Trace.WriteLine("AuthResult: Exception occurred while getting Success: " + ex.Message);
                    return false;
                }
            }
        }

        /// <summary>
        /// Dispose pattern implementation
        /// </summary>
        public void Dispose()
        {
            try
            {
                Trace.WriteLine("AuthResult: Dispose called, disposed: " + _disposed);
                if (!_disposed)
                {
                    if (_result.error_message != IntPtr.Zero)
                    {
                        Trace.WriteLine("AuthResult: Freeing error message at: " + _result.error_message);
                        WindowsAuth.auth_free_string(_result.error_message);
                    }
                    if (_result.response_data != IntPtr.Zero)
                    {
                        Trace.WriteLine("AuthResult: Freeing response data at: " + _result.response_data + ", length: " + _result.response_length);
                        WindowsAuth.auth_free_data(_result.response_data, _result.response_length);
                    }
                    _disposed = true;
                    Trace.WriteLine("AuthResult: Dispose completed");
                }
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                Trace.WriteLine("AuthResult: Exception occurred during Dispose: " + ex.Message);
                // Don't throw in Dispose as it's called during cleanup
            }
        }

        ~AuthResult()
        {
            try
            {
                Trace.WriteLine("AuthResult: Finalizer called");
                Dispose();
            }
            catch (Exception ex)
            {
                Trace.WriteLine("AuthResult: Exception occurred in finalizer: " + ex.Message);
                // Cannot throw in finalizer
            }
        }
    }

    /// <summary>
    /// Usage examples for the rust9x_windows_auth library
    /// </summary>
    public class Example
    {
        /// <summary>
        /// Helper method to write to both Console and Trace
        /// </summary>
        private static void Log(string message)
        {
            Console.WriteLine(message);
            Trace.WriteLine(message);
        }

        public static void Main()
        {
            Log("=== rust9x Windows Auth .NET Interop Example ===\n");

            try
            {
                // Step 1: Load and initialize the DLL
                Log("[1] Loading authentication library DLL...");
                try
                {
                    WindowsAuth.InitializeDll();
                    Log("DLL loaded successfully");
                }
                catch (DllLoadException ex)
                {
                    Log("Failed to load DLL: " + ex.Message);
                    Log("Make sure rust9x_windows_auth.dll is in the application directory.");
                    return;
                }

                Log("[2] Initializing authentication library...");
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Log("Failed to initialize auth library: " + initResult);
                    return;
                }
                Log("Library initialized successfully\n");

                try
                {
                    // Step 2: Set credentials (choose one method)

                    // Method A: Set credentials programmatically
                    // Console.WriteLine("[2A] Setting credentials programmatically...");
                    // AuthErrorCode credsResult = WindowsAuth.SetCredentials("username", "password", "DOMAIN");
                    // if (credsResult != AuthErrorCode.Success)
                    // {
                    //     Console.WriteLine("Failed to set credentials: " + credsResult);
                    //     return;
                    // }
                    // Console.WriteLine("Credentials set successfully\n");

                    // Method B: Prompt for credentials using Windows dialog
                    Log("[2B] Prompting for credentials via Windows dialog...");
                    bool saveCredentials = false;
                    using (AuthResult promptResult = WindowsAuth.PromptCredentials(
                        "rust9x Windows Authentication",
                        "Enter your Windows credentials for NTLM authentication",
                        saveCredentials))
                    {
                        if (!promptResult.Success)
                        {
                            Log("Credential prompt failed: " + promptResult.ErrorMessage);
                            return;
                        }
                        Log("Credentials captured successfully");
                        Log("Save credentials: " + saveCredentials + "\n");
                    }

                    // Step 3: Perform HTTP request with NTLM authentication
                    Log("[3] Performing HTTP request with NTLM authentication...");
                    string targetUrl = "http://example.com/api/test"; // Replace with your target server

                    using (AuthResult httpResult = WindowsAuth.HttpRequest(targetUrl))
                    {
                        if (httpResult.Success)
                        {
                            Log("Request successful!");
                            Log("Response length: " +
                                (httpResult.ResponseData != null ? httpResult.ResponseData.Length.ToString() : "0") + " bytes");

                            if (httpResult.ResponseString != null)
                            {
                                Log("Response: " + httpResult.ResponseString);
                            }
                        }
                        else
                        {
                            Log("Request failed: " + httpResult.ErrorMessage);
                            Log("Error code: " + httpResult.ErrorCode);
                        }
                    }
                }
                finally
                {
                    // Step 4: Cleanup
                    Log("\n[4] Cleaning up library resources...");
                    WindowsAuth.auth_cleanup();
                    Log("Cleanup complete");
                    
                    // Step 5: Unload DLL
                    Log("[5] Unloading DLL...");
                    WindowsAuth.UnloadDll();
                    Log("DLL unloaded");
                }
            }
            catch (DllLoadException ex)
            {
                Log("DLL Loading Error: " + ex.Message);
                Log("Stack trace: " + ex.StackTrace);
            }
            catch (Exception ex)
            {
                Log("Exception: " + ex.Message);
                Log("Stack trace: " + ex.StackTrace);
            }

            Log("\nPress any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// Example: NTLM token generation for custom protocol implementation
        /// </summary>
        public static void NtlmTokenExample()
        {
            Log("=== NTLM Token Generation Example ===\n");

            try
            {
                // Load DLL
                Log("Loading DLL...");
                WindowsAuth.InitializeDll();
                Log("DLL loaded successfully");

                // Initialize
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Log("Initialization failed: " + initResult);
                    return;
                }

                try
                {
                    // Set credentials
                    WindowsAuth.SetCredentials("user", "password", "DOMAIN");

                    // Note: For direct NTLM token access, you would need to extend the Rust API
                    // Currently the library handles NTLM internally for HTTP requests
                    Log("NTLM authentication is handled internally for HTTP requests");
                    Log("Use HttpRequest() method for NTLM-authenticated HTTP calls");
                }
                finally
                {
                    WindowsAuth.auth_cleanup();
                }
            }
            catch (DllLoadException ex)
            {
                Log("DLL Loading Error: " + ex.Message);
            }
            catch (Exception ex)
            {
                Log("Exception: " + ex.Message);
            }
            finally
            {
                WindowsAuth.UnloadDll();
            }
        }

        /// <summary>
        /// Example: Configuration with custom server
        /// </summary>
        public static void CustomServerExample()
        {
            Log("=== Custom Server Configuration Example ===\n");

            try
            {
                // Load DLL
                Log("Loading DLL...");
                WindowsAuth.InitializeDll();
                Log("DLL loaded successfully");
            }
            catch (DllLoadException ex)
            {
                Log("Failed to load DLL: " + ex.Message);
                return;
            }

            try
            {
                // Initialize
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Log("Initialization failed: " + initResult);
                    return;
                }

                try
                {
                    // Configure your target server
                    string serverUrl = "http://your-server.com/api/endpoint";
                    string method = "GET";

                    // Prompt for credentials
                    using (AuthResult promptResult = WindowsAuth.PromptCredentials())
                    {
                        if (!promptResult.Success)
                        {
                            Log("Credential prompt failed: " + promptResult.ErrorMessage);
                            return;
                        }
                    }

                    // Make request to custom server
                    using (AuthResult httpResult = WindowsAuth.HttpRequest(serverUrl, method, null))
                    {
                        if (httpResult.Success)
                        {
                            Log("Request to " + serverUrl + " succeeded");
                            Log("Response: " + httpResult.ResponseString);
                        }
                        else
                        {
                            Log("Request failed: " + httpResult.ErrorMessage);
                        }
                    }
                }
                finally
                {
                    WindowsAuth.auth_cleanup();
                }
            }
            catch (Exception ex)
            {
                Log("Exception: " + ex.Message);
            }
            finally
            {
                // Unload DLL
                WindowsAuth.UnloadDll();
            }
        }
    }
}
