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
        public string AuthUrl { get; set; }

        /// <summary>
        /// HTTP method to use (GET, POST, etc.)
        /// </summary>
        public string HttpMethod { get; set; }

        /// <summary>
        /// Request body for POST requests
        /// </summary>
        public string RequestBody { get; set; }

        /// <summary>
        /// Timeout for authentication requests in milliseconds
        /// </summary>
        public int TimeoutMs { get; set; }

        /// <summary>
        /// Whether to prompt for credentials automatically
        /// </summary>
        public bool AutoPromptCredentials { get; set; }

        /// <summary>
        /// Caption for credential dialog
        /// </summary>
        public string CredentialCaption { get; set; }

        /// <summary>
        /// Message for credential dialog
        /// </summary>
        public string CredentialMessage { get; set; }

        /// <summary>
        /// Whether to save credentials option
        /// </summary>
        public bool AllowSaveCredentials { get; set; }

        /// <summary>
        /// Pre-configured username (optional)
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// Pre-configured password (optional)
        /// </summary>
        public string Password { get; set; }

        /// <summary>
        /// Pre-configured domain (optional)
        /// </summary>
        public string Domain { get; set; }

        /// <summary>
        /// Maximum retry attempts for failed authentication
        /// </summary>
        public int MaxRetryAttempts { get; set; }

        /// <summary>
        /// Delay between retry attempts in milliseconds
        /// </summary>
        public int RetryDelayMs { get; set; }

        /// <summary>
        /// Whether to enable verbose logging
        /// </summary>
        public bool EnableVerboseLogging { get; set; }

        /// <summary>
        /// Log file path (if logging enabled)
        /// </summary>
        public string LogFilePath { get; set; }

        public AuthConfig()
        {
            // Set defaults
            AuthUrl = "https://example.com/api/auth";
            HttpMethod = "GET";
            RequestBody = null;
            TimeoutMs = 30000;
            AutoPromptCredentials = true;
            CredentialCaption = "Windows Authentication Required";
            CredentialMessage = "Enter your network credentials to authenticate";
            AllowSaveCredentials = false;
            Username = null;
            Password = null;
            Domain = null;
            MaxRetryAttempts = 3;
            RetryDelayMs = 1000;
            EnableVerboseLogging = false;
            LogFilePath = Path.Combine(Path.GetTempPath(), "rust9x_auth.log");
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
                if (int.TryParse(value, out int result))
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
                if (bool.TryParse(value, out bool result))
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
            if (!EnableVerboseLogging)
                return;

            try
            {
                string logMessage = string.Format("[{0:yyyy-MM-dd HH:mm:ss.fff}] {1}", DateTime.Now, message);
                System.Diagnostics.Debug.WriteLine(logMessage);

                if (!string.IsNullOrEmpty(LogFilePath))
                {
                    File.AppendAllText(LogFilePath, logMessage + Environment.NewLine);
                }
            }
            catch
            {
                // Ignore logging errors
            }
        }

        /// <summary>
        /// Create a copy of this configuration
        /// </summary>
        public AuthConfig Clone()
        {
            return new AuthConfig
            {
                AuthUrl = this.AuthUrl,
                HttpMethod = this.HttpMethod,
                RequestBody = this.RequestBody,
                TimeoutMs = this.TimeoutMs,
                AutoPromptCredentials = this.AutoPromptCredentials,
                CredentialCaption = this.CredentialCaption,
                CredentialMessage = this.CredentialMessage,
                AllowSaveCredentials = this.AllowSaveCredentials,
                Username = this.Username,
                Password = this.Password,
                Domain = this.Domain,
                MaxRetryAttempts = this.MaxRetryAttempts,
                RetryDelayMs = this.RetryDelayMs,
                EnableVerboseLogging = this.EnableVerboseLogging,
                LogFilePath = this.LogFilePath
            };
        }
    }
}
