using System;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Rust9xWindowsAuth
{
    /// <summary>
    /// High-level authentication manager with proper workflow, retries, and error handling
    /// </summary>
    public class AuthManager : IDisposable
    {
        private AuthConfig _config;
        private bool _disposed;
        private bool _initialized;

        public AuthManager()
            : this(AuthConfig.Current)
        {
        }

        public AuthManager(AuthConfig config)
        {
            if (config == null)
                throw new ArgumentNullException("config");

            if (!config.Validate())
                throw new ArgumentException("Invalid configuration", "config");

            _config = config.Clone();
            _initialized = false;
        }

        /// <summary>
        /// Initialize the authentication library
        /// </summary>
        public bool Initialize()
        {
            if (_initialized)
                return true;

            _config.Log("Initializing Rust authentication library...");

            AuthErrorCode result = WindowsAuth.auth_init();

            if (result == AuthErrorCode.Success)
            {
                _initialized = true;
                _config.Log("Authentication library initialized successfully");
                return true;
            }
            else
            {
                _config.Log("Failed to initialize authentication library: " + result);
                return false;
            }
        }

        /// <summary>
        /// Cleanup resources
        /// </summary>
        public void Cleanup()
        {
            if (!_initialized)
                return;

            _config.Log("Cleaning up authentication library...");
            WindowsAuth.auth_cleanup();
            _initialized = false;
        }

        /// <summary>
        /// Perform authentication with automatic retry logic
        /// </summary>
        public AuthResult Authenticate()
        {
            if (!_initialized)
            {
                if (!Initialize())
                {
                    return AuthResult.FromError(AuthErrorCode.NotInitialized, 
                        "Authentication library not initialized");
                }
            }

            _config.Log("Starting authentication process...");

            // Set credentials if pre-configured
            if (!string.IsNullOrEmpty(_config.Username) && 
                !string.IsNullOrEmpty(_config.Password))
            {
                _config.Log("Setting pre-configured credentials for user: " + _config.Username);
                AuthErrorCode credsResult = WindowsAuth.SetCredentials(
                    _config.Username, 
                    _config.Password, 
                    _config.Domain);

                if (credsResult != AuthErrorCode.Success)
                {
                    _config.Log("Failed to set credentials: " + credsResult);
                    return AuthResult.FromError(credsResult, 
                        "Failed to set authentication credentials");
                }
            }
            // Auto-prompt for credentials if enabled and no pre-configured credentials
            else if (_config.AutoPromptCredentials)
            {
                _config.Log("Prompting for user credentials...");
                AuthResult promptResult = PromptForCredentials();

                if (promptResult.ErrorCode != AuthErrorCode.Success)
                {
                    return promptResult;
                }
            }

            // Perform HTTP authentication request with retry logic
            return AuthenticateWithRetry();
        }

        /// <summary>
        /// Prompt for credentials using Windows dialog
        /// </summary>
        public AuthResult PromptForCredentials()
        {
            bool saveCredentials = _config.AllowSaveCredentials;

            _config.Log("Showing credential dialog: " + _config.CredentialCaption);

            AuthInteropResult result = WindowsAuth.auth_prompt_credentials(
                _config.CredentialCaption,
                _config.CredentialMessage,
                ref saveCredentials);

            AuthResult authResult = new AuthResult(result);
            _config.Log("Credential dialog result: " + authResult.ErrorCode);

            return authResult;
        }

        /// <summary>
        /// Perform HTTP request with retry logic
        /// </summary>
        private AuthResult AuthenticateWithRetry()
        {
            int attempt = 0;
            AuthResult lastResult = null;

            while (attempt < _config.MaxRetryAttempts)
            {
                attempt++;
                _config.Log(string.Format("Authentication attempt {0}/{1}", 
                    attempt, _config.MaxRetryAttempts));

                AuthResult result = PerformHttpRequest();

                if (result.ErrorCode == AuthErrorCode.Success)
                {
                    _config.Log("Authentication successful on attempt " + attempt);
                    return result;
                }

                lastResult = result;
                _config.Log("Authentication attempt " + attempt + " failed: " + result.ErrorMessage);

                // Don't retry on certain error types
                if (ShouldNotRetry(result.ErrorCode))
                {
                    _config.Log("Error type indicates no retry should occur");
                    break;
                }

                // Wait before retry if not the last attempt
                if (attempt < _config.MaxRetryAttempts)
                {
                    _config.Log("Waiting " + _config.RetryDelayMs + "ms before retry...");
                    Thread.Sleep(_config.RetryDelayMs);
                }
            }

            _config.Log("Authentication failed after " + _config.MaxRetryAttempts + " attempts");
            return lastResult ?? AuthResult.FromError(AuthErrorCode.AuthFailed, 
                "Authentication failed after " + _config.MaxRetryAttempts + " attempts");
        }

        /// <summary>
        /// Perform the actual HTTP request
        /// </summary>
        private AuthResult PerformHttpRequest()
        {
            byte[] bodyData = null;

            if (!string.IsNullOrEmpty(_config.RequestBody) && 
                _config.HttpMethod.ToUpper() == "POST")
            {
                bodyData = Encoding.UTF8.GetBytes(_config.RequestBody);
            }

            _config.Log("Making HTTP " + _config.HttpMethod + " request to: " + _config.AuthUrl);

            try
            {
                AuthResult result = WindowsAuth.HttpRequest(
                    _config.AuthUrl,
                    _config.HttpMethod,
                    bodyData);

                _config.Log("HTTP request completed with code: " + result.ErrorCode);

                if (result.ErrorCode == AuthErrorCode.Success && result.ResponseData != null)
                {
                    _config.Log("Response received, length: " + result.ResponseData.Length + " bytes");
                }

                return result;
            }
            catch (Exception ex)
            {
                _config.Log("HTTP request exception: " + ex.Message);
                return AuthResult.FromError(AuthErrorCode.NetworkError, 
                    "HTTP request failed: " + ex.Message);
            }
        }

        /// <summary>
        /// Determine if an error type should not be retried
        /// </summary>
        private bool ShouldNotRetry(AuthErrorCode errorCode)
        {
            switch (errorCode)
            {
                case AuthErrorCode.InvalidCredentials:
                case AuthErrorCode.InvalidParameter:
                case AuthErrorCode.NotInitialized:
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>
        /// Update configuration at runtime
        /// </summary>
        public void UpdateConfig(AuthConfig newConfig)
        {
            if (newConfig == null)
                throw new ArgumentNullException("newConfig");

            if (!newConfig.Validate())
                throw new ArgumentException("Invalid configuration", "newConfig");

            _config = newConfig.Clone();
            _config.Log("Configuration updated");
        }

        /// <summary>
        /// Get current configuration
        /// </summary>
        public AuthConfig Config
        {
            get { return _config.Clone(); }
        }

        /// <summary>
        /// Check if library is initialized
        /// </summary>
        public bool IsInitialized
        {
            get { return _initialized; }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                Cleanup();
                _disposed = true;
            }
            GC.SuppressFinalize(this);
        }

        ~AuthManager()
        {
            Dispose();
        }
    }

    /// <summary>
    /// Extended AuthResult with factory methods
    /// </summary>
    public partial class AuthResult
    {
        /// <summary>
        /// Create an error result
        /// </summary>
        public static AuthResult FromError(AuthErrorCode errorCode, string errorMessage)
        {
            AuthInteropResult result = new AuthInteropResult();
            result.error_code = errorCode;
            result.error_message = Marshal.StringToHGlobalAnsi(errorMessage);
            result.response_data = IntPtr.Zero;
            result.response_length = UIntPtr.Zero;

            return new AuthResult(result);
        }
    }
}
