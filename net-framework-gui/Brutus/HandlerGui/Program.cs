using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Rust9xWindowsAuth;

namespace HandlerGui
{
    static class Program
    {
        private static AuthManager authManager;
        private static AuthParameters protocolParameters;

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            try
            {
                // Parse command line arguments for protocol URLs
                protocolParameters = ParseCommandLineArgs(args);

                // Initialize AuthManager with configuration
                authManager = new AuthManager();
                
                // Apply protocol parameters to configuration if available
                if (protocolParameters != null && protocolParameters.IsValid())
                {
                    protocolParameters.ApplyToConfig(authManager.Config);
                }
                
                // Initialize the authentication library
                if (!authManager.Initialize())
                {
                    MessageBox.Show(
                        "Failed to initialize authentication library. Please check the configuration.",
                        "Initialization Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                // Register protocol handler if not already registered
                RegisterProtocolHandler();
                
                // Start with LaunchingForm, passing protocol parameters if available
                LaunchingForm launchingForm;
                if (protocolParameters != null && protocolParameters.IsValid())
                {
                    launchingForm = new LaunchingForm(
                        protocolParameters.ApplicationName,
                        protocolParameters.Publisher,
                        protocolParameters.AuthUrl);
                }
                else
                {
                    launchingForm = new LaunchingForm();
                }
                
                Application.Run(launchingForm);
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "Failed to start application: " + ex.Message,
                    "Startup Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            finally
            {
                // Cleanup authentication resources
                if (authManager != null)
                {
                    authManager.Dispose();
                }
                
                // Cleanup credential manager to ensure secure credential cleanup
                try
                {
                    CredentialManager.Instance.Shutdown();
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("Error shutting down CredentialManager: " + ex.Message);
                }
            }
        }

        /// <summary>
        /// Parse command line arguments for protocol URLs
        /// </summary>
        private static AuthParameters ParseCommandLineArgs(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                return null;
            }

            // Check if any argument is a protocol URL
            foreach (string arg in args)
            {
                if (arg.ToLower().StartsWith("rust9xauth://"))
                {
                    if (authManager != null)
                    {
                        authManager.Config.Log("Program: Detected protocol URL: " + arg);
                    }
                    return ProtocolHandler.ParseProtocolUrl(arg);
                }
            }

            return null;
        }

        /// <summary>
        /// Register the protocol handler with Windows
        /// </summary>
        private static void RegisterProtocolHandler()
        {
            try
            {
                if (!ProtocolHandler.IsProtocolRegistered())
                {
                    string appPath = ProtocolHandler.GetApplicationPath();
                    if (ProtocolHandler.RegisterProtocolHandler(appPath))
                    {
                        if (authManager != null)
                        {
                            authManager.Config.Log("Program: Successfully registered protocol handler");
                        }
                    }
                    else
                    {
                        if (authManager != null)
                        {
                            authManager.Config.Log("Program: Failed to register protocol handler");
                        }
                    }
                }
                else
                {
                    if (authManager != null)
                    {
                        authManager.Config.Log("Program: Protocol handler already registered");
                    }
                }
            }
            catch (Exception ex)
            {
                if (authManager != null)
                {
                    authManager.Config.Log("Program: Error registering protocol handler: " + ex.Message);
                }
            }
        }
        
        /// <summary>
        /// Get the global authentication manager instance
        /// </summary>
        public static AuthManager AuthManager
        {
            get { return authManager; }
        }

        /// <summary>
        /// Get the protocol parameters from command line
        /// </summary>
        public static AuthParameters ProtocolParameters
        {
            get { return protocolParameters; }
        }
    }
}