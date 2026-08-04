// .NET Framework 2.0 P/Invoke declarations for rust9x_windows_auth.dll
// This file shows how to call the Rust DLL from C# / VB.NET

using System;
using System.Runtime.InteropServices;

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
        public AuthErrorCode ErrorCode;
        public IntPtr ErrorMessage;
        public IntPtr ResponseData;
        public uint ResponseLength;
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
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern AuthErrorCode auth_init();

        /// <summary>
        /// Cleanup and free resources
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void auth_cleanup();

        /// <summary>
        /// Free a string allocated by Rust
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void auth_free_string(IntPtr ptr);

        /// <summary>
        /// Free response data allocated by Rust
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl)]
        public static extern void auth_free_data(IntPtr ptr, uint length);

        /// <summary>
        /// Set credentials for authentication
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern AuthErrorCode auth_set_credentials(
            string username,
            string password,
            string domain);

        /// <summary>
        /// Perform HTTP request with Windows Authentication
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern AuthInteropResult auth_http_request(
            string url,
            string method,
            IntPtr bodyData,
            uint bodyLength);

        /// <summary>
        /// Prompt for credentials using Windows credential dialog
        /// </summary>
        [DllImport(DLL_NAME, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern AuthInteropResult auth_prompt_credentials(
            string caption,
            string message,
            ref bool saveCredentials);

        #endregion

        #region Helper Methods

        /// <summary>
        /// Helper to set credentials
        /// </summary>
        public static AuthErrorCode SetCredentials(string username, string password, string domain)
        {
            return auth_set_credentials(username, password, domain);
        }

        /// <summary>
        /// Helper to perform HTTP GET request
        /// </summary>
        public static AuthResult HttpRequest(string url)
        {
            return HttpRequest(url, "GET", null);
        }

        /// <summary>
        /// Helper to perform HTTP request with body
        /// </summary>
        public static AuthResult HttpRequest(string url, string method, byte[] body)
        {
            IntPtr bodyPtr = IntPtr.Zero;
            uint bodyLen = 0;

            if (body != null && body.Length > 0)
            {
                bodyPtr = Marshal.AllocHGlobal(body.Length);
                Marshal.Copy(body, 0, bodyPtr, body.Length);
                bodyLen = (uint)body.Length;
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
        /// Helper to prompt for credentials
        /// </summary>
        public static AuthResult PromptCredentials(string caption, string message, bool save)
        {
            AuthInteropResult result = auth_prompt_credentials(caption, message, ref save);
            return new AuthResult(result);
        }

        #endregion
    }

    /// <summary>
    /// Wrapper for authentication results with proper disposal
    /// </summary>
    public class AuthResult : IDisposable
    {
        private AuthInteropResult _result;
        private bool _disposed;

        public AuthResult(AuthInteropResult result)
        {
            _result = result;
        }

        public AuthErrorCode ErrorCode
        {
            get { return _result.ErrorCode; }
        }

        public string ErrorMessage
        {
            get
            {
                if (_result.ErrorMessage != IntPtr.Zero)
                {
                    return Marshal.PtrToStringAnsi(_result.ErrorMessage);
                }
                return null;
            }
        }

        public byte[] ResponseData
        {
            get
            {
                if (_result.ResponseData != IntPtr.Zero && _result.ResponseLength > 0)
                {
                    byte[] data = new byte[_result.ResponseLength];
                    Marshal.Copy(_result.ResponseData, data, 0, (int)_result.ResponseLength);
                    return data;
                }
                return null;
            }
        }

        public string ResponseString
        {
            get
            {
                byte[] data = ResponseData;
                if (data != null)
                {
                    return System.Text.Encoding.UTF8.GetString(data);
                }
                return null;
            }
        }

        public bool Success
        {
            get { return _result.ErrorCode == AuthErrorCode.Success; }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_result.ErrorMessage != IntPtr.Zero)
                {
                    WindowsAuth.auth_free_string(_result.ErrorMessage);
                }
                if (_result.ResponseData != IntPtr.Zero)
                {
                    WindowsAuth.auth_free_data(_result.ResponseData, _result.ResponseLength);
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
    /// Usage example
    /// </summary>
    public class Example
    {
        public static void Main()
        {
            try
            {
                // Initialize the library
                AuthErrorCode initResult = WindowsAuth.auth_init();
                if (initResult != AuthErrorCode.Success)
                {
                    Console.WriteLine("Failed to initialize auth library: " + initResult);
                    return;
                }

                try
                {
                    // Option 1: Set credentials programmatically
                    // WindowsAuth.SetCredentials("username", "password", "DOMAIN");

                    // Option 2: Prompt for credentials using Windows dialog
                    using (AuthResult promptResult = WindowsAuth.PromptCredentials(
                        "Authentication Required",
                        "Enter your credentials to access the API",
                        false))
                    {
                        if (!promptResult.Success)
                        {
                            Console.WriteLine("Credential prompt failed: " + promptResult.ErrorMessage);
                            return;
                        }
                    }

                    // Perform HTTP request with NTLM authentication
                    using (AuthResult httpResult = WindowsAuth.HttpRequest("https://api.example.com/data"))
                    {
                        if (httpResult.Success)
                        {
                            Console.WriteLine("Request successful!");
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
                    // Cleanup
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
