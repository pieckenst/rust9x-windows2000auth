using System;
using System.Configuration;
using System.IO;

namespace Rust9xWindowsAuth
{
    /// <summary>
    /// Configuration for Windows Authentication integration
    /// Supports both app.config and runtime configuration
    /// </summary>
    public class AuthConfig
    {
        private static AuthConfig _current;
        private static readonly object _lock = new object();

        // Instance fields for .NET 2.0 compatibility
        private string _authUrl;
        private string _httpMethod;
        private string _requestBody;
        private int _timeoutMs;
        private bool _autoPromptCredentials;
        private string _credentialCaption;
        private string _credentialMessage;
        private bool _allowSaveCredentials;
        private string _username;
        private string _password;
        private string _domain;
        private int _maxRetryAttempts;
        private int _retryDelayMs;
        private bool _enableVerboseLogging;
        private string _logFilePath;
        private string _devServerHttp;
        private string _devServerHttps;
        private string _windowsAuthEndpoint;
        private string _accountLinkEndpoint;
        private string _linkStatusEndpoint;

        /// <summary>
        /// Current configuration instance
        /// </summary>
        public static AuthConfig Current
        {
            get
            {
                if (_current == null)
                {
                    lock (_lock)
                    {
                        if (_current == null)
                        {
                            _current = LoadConfig();
                        }
                    }
                }
                return _current;
            }
            set
            {
                lock (_lock)
                {
                    _current = value;
                }
            }
        }

        /// <summary>
        /// Target URL for authentication requests
        /// </summary>
        public string AuthUrl
        {
            get { return _authUrl; }
            set { _authUrl = value; }
        }

        /// <summary>
        /// HTTP method to use (GET, POST, etc.)
        /// </summary>
        public string HttpMethod
        {
            get { return _httpMethod; }
            set { _httpMethod = value; }
        }

        /// <summary>
        /// Request body for POST requests
        /// </summary>
        public string RequestBody
        {
            get { return _requestBody; }
            set { _requestBody = value; }
        }

        /// <summary>
        /// Timeout for authentication requests in milliseconds
        /// </summary>
        public int TimeoutMs
        {
            get { return _timeoutMs; }
            set { _timeoutMs = value; }
        }

        /// <summary>
        /// Whether to prompt for credentials automatically
        /// </summary>
        public bool AutoPromptCredentials
        {
            get { return _autoPromptCredentials; }
            set { _autoPromptCredentials = value; }
        }

        /// <summary>
        /// Caption for credential dialog
        /// </summary>
        public string CredentialCaption
        {
            get { return _credentialCaption; }
            set { _credentialCaption = value; }
        }

        /// <summary>
        /// Message for credential dialog
        /// </summary>
        public string CredentialMessage
        {
            get { return _credentialMessage; }
            set { _credentialMessage = value; }
        }

        /// <summary>
        /// Whether to save credentials option
        /// </summary>
        public bool AllowSaveCredentials
        {
            get { return _allowSaveCredentials; }
            set { _allowSaveCredentials = value; }
        }

        /// <summary>
        /// Pre-configured username (optional)
        /// </summary>
        public string Username
        {
            get { return _username; }
            set { _username = value; }
        }

        /// <summary>
        /// Pre-configured password (optional)
        /// </summary>
        public string Password
        {
            get { return _password; }
            set { _password = value; }
        }

        /// <summary>
        /// Pre-configured domain (optional)
        /// </summary>
        public string Domain
        {
            get { return _domain; }
            set { _domain = value; }
        }

        /// <summary>
        /// Maximum retry attempts for failed authentication
        /// </summary>
        public int MaxRetryAttempts
        {
            get { return _maxRetryAttempts; }
            set { _maxRetryAttempts = value; }
        }

        /// <summary>
        /// Delay between retry attempts in milliseconds
        /// </summary>
        public int RetryDelayMs
        {
            get { return _retryDelayMs; }
            set { _retryDelayMs = value; }
        }

        /// <summary>
        /// Whether to enable verbose logging
        /// </summary>
        public bool EnableVerboseLogging
        {
            get { return _enableVerboseLogging; }
            set { _enableVerboseLogging = value; }
        }

        /// <summary>
        /// Log file path (if logging enabled)
        /// </summary>
        public string LogFilePath
        {
            get { return _logFilePath; }
            set { _logFilePath = value; }
        }

        /// <summary>
        /// Development server HTTP endpoint
        /// </summary>
        public string DevServerHttp
        {
            get { return _devServerHttp; }
            set { _devServerHttp = value; }
        }

        /// <summary>
        /// Development server HTTPS endpoint
        /// </summary>
        public string DevServerHttps
        {
            get { return _devServerHttps; }
            set { _devServerHttps = value; }
        }

        /// <summary>
        /// Windows authentication endpoint path
        /// </summary>
        public string WindowsAuthEndpoint
        {
            get { return _windowsAuthEndpoint; }
            set { _windowsAuthEndpoint = value; }
        }

        /// <summary>
        /// Account linking endpoint path
        /// </summary>
        public string AccountLinkEndpoint
        {
            get { return _accountLinkEndpoint; }
            set { _accountLinkEndpoint = value; }
        }

        /// <summary>
        /// Link status endpoint path
        /// </summary>
        public string LinkStatusEndpoint
        {
            get { return _linkStatusEndpoint; }
            set { _linkStatusEndpoint = value; }
        }

        public AuthConfig()
        {
            // Set defaults for development server connection
            AuthUrl = "https://localhost:5001/api/v1/auth/windows/windows-login";
            HttpMethod = "GET";
            RequestBody = null;
            TimeoutMs = 30000;
            AutoPromptCredentials = true;
            CredentialCaption = "Windows Authentication Required";
            CredentialMessage = "Enter your network credentials to authenticate with BRU Avtopark";
            AllowSaveCredentials = false;
            Username = null;
            Password = null;
            Domain = null;
            MaxRetryAttempts = 3;
            RetryDelayMs = 1000;
            EnableVerboseLogging = true; // Enable by default for debugging
            LogFilePath = Path.Combine(Path.GetTempPath(), "rust9x_auth.log");
            
            // Development server endpoints
            DevServerHttp = "http://localhost:5000";
            DevServerHttps = "https://localhost:5001";
            WindowsAuthEndpoint = "/api/v1/auth/windows/windows-login";
            AccountLinkEndpoint = "/api/v1/auth/windows/link-windows-account";
            LinkStatusEndpoint = "/api/v1/auth/windows/check-windows-link-status";
        }

        /// <summary>
        /// Load configuration from app.config
        /// </summary>
        private static AuthConfig LoadConfig()
        {
            AuthConfig config = new AuthConfig();

            try
            {
                // Try to read from app.config
                config.AuthUrl = GetAppSetting("AuthUrl", config.AuthUrl);
                config.HttpMethod = GetAppSetting("HttpMethod", config.HttpMethod);
                config.RequestBody = GetAppSetting("RequestBody", config.RequestBody);
                config.TimeoutMs = GetAppSettingInt("TimeoutMs", config.TimeoutMs);
                config.AutoPromptCredentials = GetAppSettingBool("AutoPromptCredentials", config.AutoPromptCredentials);
                config.CredentialCaption = GetAppSetting("CredentialCaption", config.CredentialCaption);
                config.CredentialMessage = GetAppSetting("CredentialMessage", config.CredentialMessage);
                config.AllowSaveCredentials = GetAppSettingBool("AllowSaveCredentials", config.AllowSaveCredentials);
                config.Username = GetAppSetting("Username", config.Username);
                config.Password = GetAppSetting("Password", config.Password);
                config.Domain = GetAppSetting("Domain", config.Domain);
                config.MaxRetryAttempts = GetAppSettingInt("MaxRetryAttempts", config.MaxRetryAttempts);
                config.RetryDelayMs = GetAppSettingInt("RetryDelayMs", config.RetryDelayMs);
                config.EnableVerboseLogging = GetAppSettingBool("EnableVerboseLogging", config.EnableVerboseLogging);
                config.LogFilePath = GetAppSetting("LogFilePath", config.LogFilePath);
                
                // Development server endpoints
                config.DevServerHttp = GetAppSetting("DevServerHttp", config.DevServerHttp);
                config.DevServerHttps = GetAppSetting("DevServerHttps", config.DevServerHttps);
                config.WindowsAuthEndpoint = GetAppSetting("WindowsAuthEndpoint", config.WindowsAuthEndpoint);
                config.AccountLinkEndpoint = GetAppSetting("AccountLinkEndpoint", config.AccountLinkEndpoint);
                config.LinkStatusEndpoint = GetAppSetting("LinkStatusEndpoint", config.LinkStatusEndpoint);
            }
            catch (Exception ex)
            {
                // If config reading fails, use defaults
                System.Diagnostics.Debug.WriteLine("Failed to load auth config: " + ex.Message);
            }

            return config;
        }

        private static string GetAppSetting(string key, string defaultValue)
        {
            try
            {
                string value = ConfigurationManager.AppSettings[key];
                return string.IsNullOrEmpty(value) ? defaultValue : value;
            }
            catch
            {
                return defaultValue;
            }
        }

        private static int GetAppSettingInt(string key, int defaultValue)
        {
            try
            {
                string value = ConfigurationManager.AppSettings[key];
                int result;
                if (int.TryParse(value, out result))
                    return result;
                return defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        private static bool GetAppSettingBool(string key, bool defaultValue)
        {
            try
            {
                string value = ConfigurationManager.AppSettings[key];
                bool result;
                if (bool.TryParse(value, out result))
                    return result;
                return defaultValue;
            }
            catch
            {
                return defaultValue;
            }
        }

        /// <summary>
        /// Validate configuration
        /// </summary>
        public bool Validate()
        {
            if (string.IsNullOrEmpty(AuthUrl))
                return false;

            if (!Uri.IsWellFormedUriString(AuthUrl, UriKind.Absolute))
                return false;

            if (TimeoutMs <= 0)
                return false;

            if (MaxRetryAttempts < 0)
                return false;

            if (RetryDelayMs < 0)
                return false;

            return true;
        }

        /// <summary>
        /// Log message if verbose logging is enabled
        /// </summary>
        public void Log(string message)
        {
            try
            {
                string logMessage = string.Format("[{0:yyyy-MM-dd HH:mm:ss.fff}] {1}", DateTime.Now, message);
                System.Diagnostics.Debug.WriteLine(logMessage);

                if (!string.IsNullOrEmpty(LogFilePath))
                {
                    File.AppendAllText(LogFilePath, logMessage + Environment.NewLine);
                }
            }
            catch (Exception ex)
            {
                // Log to debug even if verbose logging is disabled, to catch logging errors
                System.Diagnostics.Debug.WriteLine("Logging error: " + ex.Message);
                System.Diagnostics.Debug.WriteLine("Original message that failed to log: " + message);
            }
        }

        /// <summary>
        /// Create a copy of this configuration
        /// </summary>
        public AuthConfig Clone()
        {
            AuthConfig clone = new AuthConfig();
            clone.AuthUrl = this.AuthUrl;
            clone.HttpMethod = this.HttpMethod;
            clone.RequestBody = this.RequestBody;
            clone.TimeoutMs = this.TimeoutMs;
            clone.AutoPromptCredentials = this.AutoPromptCredentials;
            clone.CredentialCaption = this.CredentialCaption;
            clone.CredentialMessage = this.CredentialMessage;
            clone.AllowSaveCredentials = this.AllowSaveCredentials;
            clone.Username = this.Username;
            clone.Password = this.Password;
            clone.Domain = this.Domain;
            clone.MaxRetryAttempts = this.MaxRetryAttempts;
            clone.RetryDelayMs = this.RetryDelayMs;
            clone.EnableVerboseLogging = this.EnableVerboseLogging;
            clone.LogFilePath = this.LogFilePath;
            clone.DevServerHttp = this.DevServerHttp;
            clone.DevServerHttps = this.DevServerHttps;
            clone.WindowsAuthEndpoint = this.WindowsAuthEndpoint;
            clone.AccountLinkEndpoint = this.AccountLinkEndpoint;
            clone.LinkStatusEndpoint = this.LinkStatusEndpoint;
            return clone;
        }

        /// <summary>
        /// Clear sensitive data from configuration
        /// </summary>
        public void ClearSensitiveData()
        {
            _username = null;
            _password = null;
            _domain = null;
        }
    }
}
