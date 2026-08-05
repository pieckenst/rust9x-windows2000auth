using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Rust9xWindowsAuth;

namespace HandlerGui
{
    static class Program
    {
        private static AuthManager authManager;

        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            
            try
            {
                // Initialize AuthManager with configuration
                authManager = new AuthManager();
                
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
                
                // Start with LaunchingForm
                Application.Run(new LaunchingForm());
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
            }
        }
        
        /// <summary>
        /// Get the global authentication manager instance
        /// </summary>
        public static AuthManager AuthManager
        {
            get { return authManager; }
        }
    }
}