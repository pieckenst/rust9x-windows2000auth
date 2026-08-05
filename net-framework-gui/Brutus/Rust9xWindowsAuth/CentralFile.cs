// .NET Framework 2.0+ P/Invoke declarations for rust9x_windows_auth.dll
// This file shows how to call the Rust DLL from C# / VB.NET
// Compatible with .NET Framework 2.0 and later versions

using System;
using System.Runtime.InteropServices;
using System.Text;

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
    /// P/Invoke wrapper for rust9x_windows_auth.dll
    /// </summary>
    public static class WindowsAuth
    {
        private const string DLL_NAME = "rust9x_windows_auth.dll";

        #region DLL Imports

        /// <summary>
        /// Initialize the authentication library
        /// Must be called before any other operations
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern AuthErrorCode auth_init();

        /// <summary>
        /// Cleanup and free resources
        /// Should be called when done using the library
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void auth_cleanup();

        /// <summary>
        /// Free a string allocated by Rust
        /// Used to free error messages returned by the library
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void auth_free_string(IntPtr ptr);

        /// <summary>
        /// Free response data allocated by Rust
        /// Used to free HTTP response data
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void auth_free_data(IntPtr ptr, UIntPtr length);

        /// <summary>
        /// Set credentials for authentication programmatically
        /// </summary>
        /// <param name="username">Username</param>
        /// <param name="password">Password</param>
        /// <param name="domain">Domain (can be null or empty for local account)</param>
        /// <returns>Error code indicating success or failure</returns>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern AuthErrorCode auth_set_credentials(
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
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern AuthInteropResult auth_http_request(
            string url,
            string method,
            IntPtr bodyData,
            UIntPtr bodyLength);

        /// <summary>
        /// Prompt for credentials using Windows credential dialog
        /// </summary>
        /// <param name="caption">Dialog caption/title</param>
        /// <param name="message">Dialog message/instructions</param>
        /// <param name="saveCredentials">Reference to boolean for save checkbox state</param>
        /// <returns>Result structure indicating success or failure</returns>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern AuthInteropResult auth_prompt_credentials(
            string caption,
            string message,
            ref bool saveCredentials);

        #endregion

        #region Helper Methods

        /// <summary>
        /// Helper to set credentials programmatically
        /// </summary>
        public static AuthErrorCode SetCredentials(string username, string password, string domain)
        {
            return auth_set_credentials(username, password, domain);
        }

        /// <summary>
        /// Helper to set credentials for local account (no domain)
        /// </summary>
        public static AuthErrorCode SetCredentials(string username, string password)
        {
            return auth_set_credentials(username, password, null);
        }

        /// <summary>
        /// Helper to perform HTTP GET request
        /// </summary>
        public static AuthResult HttpRequest(string url)
        {
            return HttpRequest(url, "GET", null);
        }

        /// <summary>
        /// Helper to perform HTTP POST request with body
        /// </summary>
        public static AuthResult HttpPost(string url, byte[] body)
        {
            return HttpRequest(url, "POST", body);
        }

        /// <summary>
        /// Helper to perform HTTP request with method and optional body
        /// </summary>
        public static AuthResult HttpRequest(string url, string method, byte[] body)
        {
            IntPtr bodyPtr = IntPtr.Zero;
            UIntPtr bodyLen = UIntPtr.Zero;

            if (body != null && body.Length > 0)
            {
                bodyPtr = Marshal.AllocHGlobal(body.Length);
                Marshal.Copy(body, 0, bodyPtr, body.Length);
                bodyLen = (UIntPtr)body.Length;
            }

            try
            {
                AuthInteropResult result = auth_http_request(url, method, bodyPtr, bodyLen);
                return new AuthResult(result);
            }
            finally
            {
                if (bodyPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(bodyPtr);
                }
            }
        }

        /// <summary>
        /// Helper to prompt for credentials using Windows dialog
        /// </summary>
        public static AuthResult PromptCredentials(string caption, string message, bool save)
        {
            AuthInteropResult result = auth_prompt_credentials(caption, message, ref save);
            return new AuthResult(result);
        }

        /// <summary>
        /// Helper to prompt for credentials with default settings
        /// </summary>
        public static AuthResult PromptCredentials()
        {
            bool save = false;
            return PromptCredentials(
                "Windows Authentication",
                "Enter your credentials to continue",
                save);
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

        public AuthResult(AuthInteropResult result)
        {
            _result = result;
        }

        /// <summary>
        /// Error code from the operation
        /// </summary>
        public AuthErrorCode ErrorCode
        {
            get { return _result.error_code; }
        }

        /// <summary>
        /// Error message (if any), automatically freed on disposal
        /// </summary>
        public string ErrorMessage
        {
            get
            {
                if (_result.error_message != IntPtr.Zero)
                {
                    return Marshal.PtrToStringAnsi(_result.error_message);
                }
                return null;
            }
        }

        /// <summary>
        /// Raw response data bytes (if any), automatically freed on disposal
        /// </summary>
        public byte[] ResponseData
        {
            get
            {
                if (_result.response_data != IntPtr.Zero && _result.response_length != UIntPtr.Zero)
                {
                    byte[] data = new byte[(int)_result.response_length];
                    Marshal.Copy(_result.response_data, data, 0, (int)_result.response_length);
                    return data;
                }
                return null;
            }
        }

        /// <summary>
        /// Response data as UTF-8 string (if any)
        /// </summary>
        public string ResponseString
        {
            get
            {
                byte[] data = ResponseData;
                if (data != null)
                {
                    return Encoding.UTF8.GetString(data);
                }
                return null;
            }
        }

        /// <summary>
        /// Whether the operation completed successfully
        /// </summary>
        public bool Success
        {
            get { return _result.error_code == AuthErrorCode.Success; }
        }

        /// <summary>
        /// Dispose pattern implementation
        /// </summary>
        public void Dispose()
        {
            if (!_disposed)
            {
                if (_result.error_message != IntPtr.Zero)
                {
                    WindowsAuth.auth_free_string(_result.error_message);
                }
                if (_result.response_data != IntPtr.Zero)
                {
                    WindowsAuth.auth_free_data(_result.response_data, _result.response_length);
                }
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        ~AuthResult()
        {
            Dispose();
        }
    }

    /// <summary>
    /// Usage examples for the rust9x_windows_auth library
    /// </summary>
    public class Example
    {
        public static void Main()
        {
            Console.WriteLine("=== rust9x Windows Auth .NET Interop Example ===\n");

            try
            {
                // Step 1: Initialize the library
                Console.WriteLine("[1] Initializing authentication library...");
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Console.WriteLine("Failed to initialize auth library: " + initResult);
                    return;
                }
                Console.WriteLine("Library initialized successfully\n");

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
                    Console.WriteLine("[2B] Prompting for credentials via Windows dialog...");
                    bool saveCredentials = false;
                    using (AuthResult promptResult = WindowsAuth.PromptCredentials(
                        "rust9x Windows Authentication",
                        "Enter your Windows credentials for NTLM authentication",
                        saveCredentials))
                    {
                        if (!promptResult.Success)
                        {
                            Console.WriteLine("Credential prompt failed: " + promptResult.ErrorMessage);
                            return;
                        }
                        Console.WriteLine("Credentials captured successfully");
                        Console.WriteLine("Save credentials: " + saveCredentials + "\n");
                    }

                    // Step 3: Perform HTTP request with NTLM authentication
                    Console.WriteLine("[3] Performing HTTP request with NTLM authentication...");
                    string targetUrl = "http://example.com/api/test"; // Replace with your target server

                    using (AuthResult httpResult = WindowsAuth.HttpRequest(targetUrl))
                    {
                        if (httpResult.Success)
                        {
                            Console.WriteLine("Request successful!");
                            Console.WriteLine("Response length: " +
                                (httpResult.ResponseData != null ? httpResult.ResponseData.Length.ToString() : "0") + " bytes");

                            if (httpResult.ResponseString != null)
                            {
                                Console.WriteLine("Response: " + httpResult.ResponseString);
                            }
                        }
                        else
                        {
                            Console.WriteLine("Request failed: " + httpResult.ErrorMessage);
                            Console.WriteLine("Error code: " + httpResult.ErrorCode);
                        }
                    }
                }
                finally
                {
                    // Step 4: Cleanup
                    Console.WriteLine("\n[4] Cleaning up library resources...");
                    WindowsAuth.auth_cleanup();
                    Console.WriteLine("Cleanup complete");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
                Console.WriteLine("Stack trace: " + ex.StackTrace);
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        /// <summary>
        /// Example: NTLM token generation for custom protocol implementation
        /// </summary>
        public static void NtlmTokenExample()
        {
            Console.WriteLine("=== NTLM Token Generation Example ===\n");

            try
            {
                // Initialize
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Console.WriteLine("Initialization failed: " + initResult);
                    return;
                }

                try
                {
                    // Set credentials
                    WindowsAuth.SetCredentials("user", "password", "DOMAIN");

                    // Note: For direct NTLM token access, you would need to extend the Rust API
                    // Currently the library handles NTLM internally for HTTP requests
                    Console.WriteLine("NTLM authentication is handled internally for HTTP requests");
                    Console.WriteLine("Use HttpRequest() method for NTLM-authenticated HTTP calls");
                }
                finally
                {
                    WindowsAuth.auth_cleanup();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception: " + ex.Message);
            }
        }

        /// <summary>
        /// Example: Configuration with custom server
        /// </summary>
        public static void CustomServerExample()
        {
            Console.WriteLine("=== Custom Server Configuration Example ===\n");

            try
            {
                // Initialize
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Console.WriteLine("Initialization failed: " + initResult);
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
                            Console.WriteLine("Credential prompt failed: " + promptResult.ErrorMessage);
                            return;
                        }
                    }

                    // Make request to custom server
                    using (AuthResult httpResult = WindowsAuth.HttpRequest(serverUrl, method, null))
                    {
                        if (httpResult.Success)
                        {
                            Console.WriteLine("Request to " + serverUrl + " succeeded");
                            Console.WriteLine("Response: " + httpResult.ResponseString);
                        }
                        else
                        {
                            Console.WriteLine("Request failed: " + httpResult.ErrorMessage);
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
                Console.WriteLine("Exception: " + ex.Message);
            }
        }
    }
}
