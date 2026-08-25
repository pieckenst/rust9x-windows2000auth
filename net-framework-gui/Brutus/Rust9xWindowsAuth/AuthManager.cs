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
            return Authenticate(null);
        }

        /// <summary>
        /// Perform authentication with automatic retry logic and optional credential container
        /// </summary>
        /// <param name="credentialContainer">Optional pre-provided credentials</param>
        public AuthResult Authenticate(CredentialContainer credentialContainer)
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

            // Use provided credentials if available
            if (credentialContainer != null && credentialContainer.HasCredentials())
            {
                _config.Log("Using provided credential container");
                AuthResult setCredsResult = SetCredentialsFromContainer(credentialContainer);
                if (setCredsResult.ErrorCode != AuthErrorCode.Success)
                {
                    return setCredsResult;
                }
            }
            // Set credentials if pre-configured
            else if (!string.IsNullOrEmpty(_config.Username) && 
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
            try
            {
                int saveCredentials = _config.AllowSaveCredentials ? 1 : 0;

                _config.Log("Showing credential dialog: " + _config.CredentialCaption);
                _config.Log("PromptForCredentials: Config.Username BEFORE prompt: " + (_config.Username ?? "(null)"));
                _config.Log("PromptForCredentials: Config.Password BEFORE prompt: " + (_config.Password != null ? "PRESENT (" + _config.Password.Length + " chars)" : "(null)"));

                AuthInteropResult result;
                WindowsAuth.auth_prompt_credentials(
                    _config.CredentialCaption,
                    _config.CredentialMessage,
                    ref saveCredentials,
                    out result);

                AuthResult authResult = new AuthResult(result);
                _config.Log("Credential dialog result: " + authResult.ErrorCode);
                
                // If prompt was successful, retrieve the credentials from the Rust library
                if (authResult.ErrorCode == AuthErrorCode.Success)
                {
                    _config.Log("PromptForCredentials: Retrieving credentials from Rust library");
                    
                    try
                    {
                        System.Text.StringBuilder username = new System.Text.StringBuilder(256);
                        System.Text.StringBuilder password = new System.Text.StringBuilder(256);
                        System.Text.StringBuilder domain = new System.Text.StringBuilder(256);
                        
                        AuthInteropResult getCredsResult;
                        WindowsAuth.auth_get_credentials(username, password, domain, out getCredsResult);
                        
                        if (getCredsResult.error_code == AuthErrorCode.Success)
                        {
                            _config.Username = username.ToString();
                            _config.Password = password.ToString();
                            _config.Domain = domain.ToString();
                            
                            _config.Log("PromptForCredentials: Credentials retrieved from Rust library");
                            _config.Log("PromptForCredentials: Username: " + _config.Username);
                            _config.Log("PromptForCredentials: Password: PRESENT (" + _config.Password.Length + " chars)");
                            _config.Log("PromptForCredentials: Domain: " + (_config.Domain ?? "(null)"));
                        }
                        else
                        {
                            _config.Log("PromptForCredentials: Failed to retrieve credentials from Rust library: " + getCredsResult.error_code);
                        }
                    }
                    catch (Exception credsEx)
                    {
                        _config.Log("PromptForCredentials: Exception retrieving credentials: " + credsEx.Message);
                    }
                }
                
                // Debug: Check if credentials were set in config after prompt
                _config.Log("PromptForCredentials: Config.Username AFTER prompt: " + (_config.Username ?? "(null)"));
                _config.Log("PromptForCredentials: Config.Password AFTER prompt: " + (_config.Password != null ? "PRESENT (" + _config.Password.Length + " chars)" : "(null)"));
                _config.Log("PromptForCredentials: Config.Domain AFTER prompt: " + (_config.Domain ?? "(null)"));

                return authResult;
            }
            catch (Exception ex)
            {
                _config.Log("EXCEPTION TYPE: " + ex.GetType().FullName);
                _config.Log("MESSAGE: " + ex.Message);
                _config.Log("STACK TRACE:\r\n" + ex.StackTrace);
                
                if (ex.InnerException != null)
                {
                    _config.Log("INNER TYPE: " + ex.InnerException.GetType().FullName);
                    _config.Log("INNER MESSAGE: " + ex.InnerException.Message);
                    _config.Log("INNER STACK:\r\n" + ex.InnerException.StackTrace);
                }
                
                _config.Log("PromptForCredentials: Exception occurred: " + ex.Message);
                throw;
            }
        }

        /// <summary>
        /// Set credentials from a CredentialContainer (secure credential passing)
        /// </summary>
        /// <param name="credentialContainer">Container with credentials to set</param>
        /// <returns>AuthResult indicating success or failure</returns>
        public AuthResult SetCredentialsFromContainer(CredentialContainer credentialContainer)
        {
            if (credentialContainer == null)
            {
                _config.Log("SetCredentialsFromContainer: Credential container is null");
                return AuthResult.FromError(AuthErrorCode.InvalidParameter, 
                    "Credential container cannot be null");
            }

            if (!credentialContainer.HasCredentials())
            {
                _config.Log("SetCredentialsFromContainer: Credential container is empty or invalid");
                return AuthResult.FromError(AuthErrorCode.InvalidParameter, 
                    "Credential container does not contain valid credentials");
            }

            try
            {
                string username = credentialContainer.GetUsername();
                string password = credentialContainer.GetPassword();
                string domain = credentialContainer.GetDomain();

                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    _config.Log("SetCredentialsFromContainer: Username or password is empty");
                    return AuthResult.FromError(AuthErrorCode.InvalidParameter, 
                        "Username and password are required");
                }

                _config.Log("Setting credentials from container for user: " + username);

                AuthErrorCode result = WindowsAuth.SetCredentials(username, password, domain);

                // Clear sensitive data immediately
                if (username != null)
                {
                    char[] usernameChars = username.ToCharArray();
                    Array.Clear(usernameChars, 0, usernameChars.Length);
                }
                if (password != null)
                {
                    char[] passwordChars = password.ToCharArray();
                    Array.Clear(passwordChars, 0, passwordChars.Length);
                }
                if (domain != null)
                {
                    char[] domainChars = domain.ToCharArray();
                    Array.Clear(domainChars, 0, domainChars.Length);
                }

                if (result == AuthErrorCode.Success)
                {
                    _config.Log("Credentials set successfully from container");
                    return AuthResult.FromError(AuthErrorCode.Success, "Credentials set successfully");
                }
                else
                {
                    _config.Log("Failed to set credentials from container: " + result);
                    return AuthResult.FromError(result, "Failed to set credentials");
                }
            }
            catch (Exception ex)
            {
                _config.Log("EXCEPTION TYPE: " + ex.GetType().FullName);
                _config.Log("MESSAGE: " + ex.Message);
                _config.Log("STACK TRACE:\r\n" + ex.StackTrace);
                
                if (ex.InnerException != null)
                {
                    _config.Log("INNER TYPE: " + ex.InnerException.GetType().FullName);
                    _config.Log("INNER MESSAGE: " + ex.InnerException.Message);
                    _config.Log("INNER STACK:\r\n" + ex.InnerException.StackTrace);
                }
                
                _config.Log("SetCredentialsFromContainer: Exception occurred: " + ex.Message);
                return AuthResult.FromError(AuthErrorCode.Unknown, 
                    "Exception while setting credentials: " + ex.Message);
            }
        }

        /// <summary>
        /// Check if credentials are already configured and valid
        /// </summary>
        /// <returns>True if credentials are available</returns>
        public bool HasCredentials()
        {
            return !string.IsNullOrEmpty(_config.Username) && 
                   !string.IsNullOrEmpty(_config.Password);
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
    /// Extended AuthResult with factory methods for .NET Framework 2.0 compatibility
    /// </summary>
    public partial class AuthResult
    {
        /// <summary>
        /// Create an error result with proper error code and message
        /// </summary>
        /// <param name="errorCode">The error code to return</param>
        /// <param name="errorMessage">The error message to return</param>
        /// <returns>A new AuthResult with the specified error details</returns>
        public static AuthResult FromError(AuthErrorCode errorCode, string errorMessage)
        {
            try
            {
                AuthInteropResult result = new AuthInteropResult();
                result.error_code = errorCode;
                
                // Allocate memory for the error message
                if (!string.IsNullOrEmpty(errorMessage))
                {
                    result.error_message = Marshal.StringToHGlobalAnsi(errorMessage);
                }
                else
                {
                    result.error_message = IntPtr.Zero;
                }
                
                result.response_data = IntPtr.Zero;
                result.response_length = UIntPtr.Zero;

                return new AuthResult(result);
            }
            catch (Exception ex)
            {
                // Fallback to direct constructor if marshaling fails
                System.Diagnostics.Debug.WriteLine("FromError: Exception during marshaling: " + ex.Message);
                return new AuthResult(errorCode, errorMessage ?? "Unknown error");
            }
        }
    }
}
