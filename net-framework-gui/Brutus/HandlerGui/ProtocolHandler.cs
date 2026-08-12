using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.Diagnostics;
using Microsoft.Win32;
using System.Windows.Forms;

namespace HandlerGui
{
    /// <summary>
    /// Handles custom URL protocol registration and parsing for authentication requests
    /// Supports protocol format: rust9xauth://auth?app=AppName&pub=Publisher&url=TargetUrl
    /// </summary>
    public class ProtocolHandler
    {
        private const string PROTOCOL_NAME = "rust9xauth";
        private const string PROTOCOL_DISPLAY_NAME = "Rust9x Windows Authentication";
        private const string PROTOCOL_DESCRIPTION = "Handle Windows authentication requests for legacy systems";

        /// <summary>
        /// Parse authentication parameters from protocol URL
        /// </summary>
        public static AuthParameters ParseProtocolUrl(string url)
        {
            AuthParameters parameters = new AuthParameters();

            try
            {
                if (string.IsNullOrEmpty(url))
                {
                    return parameters;
                }

                // Parse protocol URL format: rust9xauth://auth?app=AppName&pub=Publisher&url=TargetUrl
                Uri uri = new Uri(url);

                // Check if it's our protocol
                if (uri.Scheme != PROTOCOL_NAME)
                {
                    throw new ArgumentException("Invalid protocol scheme: " + uri.Scheme);
                }

                // Parse query parameters
                string query = uri.Query;
                if (!string.IsNullOrEmpty(query))
                {
                    // Remove leading '?' and parse parameters
                    query = query.Substring(1);
                    string[] pairs = query.Split(new char[] { '&' });

                    foreach (string pair in pairs)
                    {
                        string[] keyValue = pair.Split(new char[] { '=' });
                        if (keyValue.Length == 2)
                        {
                            string key = Uri.UnescapeDataString(keyValue[0]).ToLower();
                            string value = Uri.UnescapeDataString(keyValue[1]);

                            switch (key)
                            {
                                case "app":
                                case "application":
                                    parameters.ApplicationName = value;
                                    break;
                                case "pub":
                                case "publisher":
                                    parameters.Publisher = value;
                                    break;
                                case "url":
                                case "target":
                                case "authurl":
                                    parameters.AuthUrl = value;
                                    break;
                                case "method":
                                    parameters.HttpMethod = value;
                                    break;
                                case "returnurl":
                                case "callback":
                                    parameters.ReturnUrl = value;
                                    break;
                                case "token":
                                    parameters.RequestToken = value;
                                    break;
                            }
                        }
                    }
                }

                return parameters;
            }
            catch (Exception ex)
            {
                Debug.WriteLine("ProtocolHandler: Error parsing URL '" + url + "': " + ex.Message);
                return parameters;
            }
        }

        /// <summary>
        /// Register the custom protocol handler with Windows
        /// </summary>
        public static bool RegisterProtocolHandler(string applicationPath)
        {
            try
            {
                RegistryKey rootKey = Registry.CurrentUser.OpenSubKey("Software\\Classes", true);
                if (rootKey == null)
                {
                    Debug.WriteLine("ProtocolHandler: Could not open Software\\Classes registry key");
                    return false;
                }

                try
                {
                    // Create protocol key
                    RegistryKey protocolKey = rootKey.CreateSubKey(PROTOCOL_NAME);
                    if (protocolKey == null)
                    {
                        Debug.WriteLine("ProtocolHandler: Could not create protocol key");
                        return false;
                    }

                    try
                    {
                        // Set default value (display name)
                        protocolKey.SetValue("", PROTOCOL_DISPLAY_NAME);
                        protocolKey.SetValue("URL Protocol", "");

                        // Create shell/open/command key
                        RegistryKey shellKey = protocolKey.CreateSubKey("shell");
                        RegistryKey openKey = shellKey.CreateSubKey("open");
                        RegistryKey commandKey = openKey.CreateSubKey("command");

                        if (commandKey == null)
                        {
                            Debug.WriteLine("ProtocolHandler: Could not create command key");
                            return false;
                        }

                        try
                        {
                            // Set command to launch application with URL parameter
                            string command = "\"" + applicationPath + "\" \"%1\"";
                            commandKey.SetValue("", command);
                        }
                        finally
                        {
                            commandKey.Close();
                        }

                        // Create DefaultIcon key
                        RegistryKey iconKey = protocolKey.CreateSubKey("DefaultIcon");
                        if (iconKey != null)
                        {
                            try
                            {
                                iconKey.SetValue("", applicationPath + ",0");
                            }
                            finally
                            {
                                iconKey.Close();
                            }
                        }
                    }
                    finally
                    {
                        protocolKey.Close();
                    }

                    Debug.WriteLine("ProtocolHandler: Successfully registered protocol '" + PROTOCOL_NAME + "'");
                    return true;
                }
                finally
                {
                    rootKey.Close();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("ProtocolHandler: Error registering protocol handler: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Unregister the custom protocol handler from Windows
        /// </summary>
        public static bool UnregisterProtocolHandler()
        {
            try
            {
                RegistryKey rootKey = Registry.CurrentUser.OpenSubKey("Software\\Classes", true);
                if (rootKey == null)
                {
                    return false;
                }

                try
                {
                    rootKey.DeleteSubKeyTree(PROTOCOL_NAME);
                    Debug.WriteLine("ProtocolHandler: Successfully unregistered protocol '" + PROTOCOL_NAME + "'");
                    return true;
                }
                finally
                {
                    rootKey.Close();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine("ProtocolHandler: Error unregistering protocol handler: " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Check if the protocol handler is registered
        /// </summary>
        public static bool IsProtocolRegistered()
        {
            try
            {
                RegistryKey rootKey = Registry.CurrentUser.OpenSubKey("Software\\Classes");
                if (rootKey == null)
                {
                    return false;
                }

                try
                {
                    RegistryKey protocolKey = rootKey.OpenSubKey(PROTOCOL_NAME);
                    if (protocolKey != null)
                    {
                        protocolKey.Close();
                        return true;
                    }
                    return false;
                }
                finally
                {
                    rootKey.Close();
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Get the current application path for protocol registration
        /// </summary>
        public static string GetApplicationPath()
        {
            try
            {
                return System.Reflection.Assembly.GetExecutingAssembly().Location;
            }
            catch
            {
                return Application.ExecutablePath;
            }
        }

        /// <summary>
        /// Build a protocol URL for launching authentication
        /// </summary>
        public static string BuildProtocolUrl(AuthParameters parameters)
        {
            StringBuilder url = new StringBuilder();
            url.Append(PROTOCOL_NAME);
            url.Append("://auth?");

            System.Collections.Specialized.StringCollection queryParams = new System.Collections.Specialized.StringCollection();

            if (!string.IsNullOrEmpty(parameters.ApplicationName))
            {
                queryParams.Add("app=" + Uri.EscapeDataString(parameters.ApplicationName));
            }

            if (!string.IsNullOrEmpty(parameters.Publisher))
            {
                queryParams.Add("pub=" + Uri.EscapeDataString(parameters.Publisher));
            }

            if (!string.IsNullOrEmpty(parameters.AuthUrl))
            {
                queryParams.Add("url=" + Uri.EscapeDataString(parameters.AuthUrl));
            }

            if (!string.IsNullOrEmpty(parameters.HttpMethod))
            {
                queryParams.Add("method=" + Uri.EscapeDataString(parameters.HttpMethod));
            }

            if (!string.IsNullOrEmpty(parameters.ReturnUrl))
            {
                queryParams.Add("returnurl=" + Uri.EscapeDataString(parameters.ReturnUrl));
            }

            if (!string.IsNullOrEmpty(parameters.RequestToken))
            {
                queryParams.Add("token=" + Uri.EscapeDataString(parameters.RequestToken));
            }

            bool first = true;
            foreach (string param in queryParams)
            {
                if (!first)
                {
                    url.Append("&");
                }
                url.Append(param);
                first = false;
            }

            return url.ToString();
        }
    }

    /// <summary>
    /// Parameters extracted from protocol URL
    /// </summary>
    public class AuthParameters
    {
        private string applicationName;
        private string publisher;
        private string authUrl;
        private string httpMethod;
        private string returnUrl;
        private string requestToken;

        public string ApplicationName
        {
            get { return applicationName; }
            set { applicationName = value; }
        }

        public string Publisher
        {
            get { return publisher; }
            set { publisher = value; }
        }

        public string AuthUrl
        {
            get { return authUrl; }
            set { authUrl = value; }
        }

        public string HttpMethod
        {
            get { return httpMethod; }
            set { httpMethod = value; }
        }

        public string ReturnUrl
        {
            get { return returnUrl; }
            set { returnUrl = value; }
        }

        public string RequestToken
        {
            get { return requestToken; }
            set { requestToken = value; }
        }

        public AuthParameters()
        {
            applicationName = string.Empty;
            publisher = string.Empty;
            authUrl = string.Empty;
            httpMethod = "GET";
            returnUrl = string.Empty;
            requestToken = string.Empty;
        }

        /// <summary>
        /// Check if parameters are valid for authentication
        /// </summary>
        public bool IsValid()
        {
            return !string.IsNullOrEmpty(authUrl);
        }

        /// <summary>
        /// Apply parameters to AuthConfig
        /// </summary>
        public void ApplyToConfig(Rust9xWindowsAuth.AuthConfig config)
        {
            if (!string.IsNullOrEmpty(authUrl))
            {
                config.AuthUrl = authUrl;
            }

            if (!string.IsNullOrEmpty(httpMethod))
            {
                config.HttpMethod = httpMethod;
            }
        }
    }
}