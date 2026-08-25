using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using Rust9xWindowsAuth;

namespace HandlerGui
{
    public partial class LaunchingForm : Form
    {
        private AuthManager authManager;
        private string applicationName;
        private string publisher;
        private string requestedUrl;
        private Timer displayTimer;
        private int displaySecondsRemaining;
        private const int MINIMUM_DISPLAY_SECONDS = 100; // 100 seconds

        public LaunchingForm()
        {
            InitializeComponent();
            InitializeForm();
        }

        public LaunchingForm(string appName, string pubName, string url) : this()
        {
            applicationName = appName;
            publisher = pubName;
            requestedUrl = url;
        }

        private void InitializeForm()
        {
            // Get the global auth manager from Program
            authManager = Program.AuthManager;

            if (authManager == null)
            {
                MessageBox.Show(
                    "Authentication manager not initialized. Please restart the application.",
                    "Initialization Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                this.Close();
                return;
            }

            // Set default values if not provided
            if (string.IsNullOrEmpty(applicationName))
            {
                applicationName = "WindowsApplication1";
            }
            if (string.IsNullOrEmpty(publisher))
            {
                publisher = "Unknown Publisher";
            }
            if (string.IsNullOrEmpty(requestedUrl))
            {
                requestedUrl = AuthConfig.Current.AuthUrl;
            }

            // Initialize the display timer
            displayTimer = new Timer();
            displayTimer.Interval = 1000; // 1 second intervals
            displayTimer.Tick += new EventHandler(DisplayTimer_Tick);

            // Update UI with application information
            UpdateApplicationInfo();
        }

        private void UpdateApplicationInfo()
        {
            // Update labels with application information
            // This would typically update the form's UI elements
            // For now, we'll log the information
            authManager.Config.Log("LaunchingForm: Application=" + applicationName + 
                                 ", Publisher=" + publisher + 
                                 ", URL=" + requestedUrl);
            
            // Try to update a status label if it exists
            try
            {
                Control[] statusLabels = this.Controls.Find("lblStatus", true);
                if (statusLabels.Length > 0 && statusLabels[0] is Label)
                {
                    ((Label)statusLabels[0]).Text = "Preparing authentication...";
                }
            }
            catch
            {
                // Label may not exist, ignore error
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            // Start the display timer and then the authentication flow
            displaySecondsRemaining = MINIMUM_DISPLAY_SECONDS;
            displayTimer.Start();
            
            authManager.Config.Log("LaunchingForm: Starting display timer for " + MINIMUM_DISPLAY_SECONDS + " seconds");
            
            // Start the authentication flow after the minimum display time
            StartAuthenticationFlowDelayed();
        }

        private void DisplayTimer_Tick(object sender, EventArgs e)
        {
            displaySecondsRemaining--;
            
            // Update the countdown display
            try
            {
                Control[] countdownLabels = this.Controls.Find("lblCountdown", true);
                if (countdownLabels.Length > 0 && countdownLabels[0] is Label)
                {
                    int minutes = displaySecondsRemaining / 60;
                    int seconds = displaySecondsRemaining % 60;
                    ((Label)countdownLabels[0]).Text = string.Format("Time remaining: {0}:{1:00}", minutes, seconds);
                }
                
                Control[] statusLabels = this.Controls.Find("lblStatus", true);
                if (statusLabels.Length > 0 && statusLabels[0] is Label)
                {
                    ((Label)statusLabels[0]).Text = "Preparing authentication in " + displaySecondsRemaining + " seconds...";
                }
            }
            catch
            {
                // Labels may not exist, ignore error
            }

            if (displaySecondsRemaining <= 0)
            {
                displayTimer.Stop();
                authManager.Config.Log("LaunchingForm: Display timer completed, proceeding with authentication");
                StartAuthenticationFlow();
            }
        }

        private void StartAuthenticationFlowDelayed()
        {
            // This method is called immediately, but the actual flow
            // will proceed after the timer completes
            authManager.Config.Log("LaunchingForm: Authentication flow scheduled for " + MINIMUM_DISPLAY_SECONDS + " seconds");
        }

        private void StartAuthenticationFlow()
        {
            try
            {
                authManager.Config.Log("LaunchingForm: Starting authentication flow");

                // Update configuration with the requested URL
                if (!string.IsNullOrEmpty(requestedUrl))
                {
                    AuthConfig config = authManager.Config;
                    config.AuthUrl = requestedUrl;
                    authManager.UpdateConfig(config);
                }

                // Show the confirmation form to get user approval
                ShowConfirmationForm();
            }
            catch (Exception ex)
            {
                authManager.Config.Log("LaunchingForm: Error starting authentication flow: " + ex.Message);
                MessageBox.Show(
                    "Failed to start authentication: " + ex.Message,
                    "Authentication Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                this.Close();
            }
        }

        private void ShowConfirmationForm()
        {
            authManager.Config.Log("LaunchingForm: Showing confirmation form");

            // Create and show the confirmation form with application details
            ConfirmForm confirmForm = new ConfirmForm(applicationName, publisher, requestedUrl);
            DialogResult result = confirmForm.ShowDialog(this);

            if (result == DialogResult.OK)
            {
                // User confirmed - proceed with authentication
                authManager.Config.Log("LaunchingForm: User confirmed authentication");
                ShowInstallingForm();
            }
            else
            {
                // User cancelled - close the application
                authManager.Config.Log("LaunchingForm: User cancelled authentication");
                this.DialogResult = DialogResult.Cancel;
                this.Close();
            }
        }

        private void ShowInstallingForm()
        {
            authManager.Config.Log("LaunchingForm: Showing installing form for authentication progress");

            // Create and show the installing form to display authentication progress
            InstallingForm installingForm = new InstallingForm(applicationName, publisher);
            DialogResult result = installingForm.ShowDialog(this);

            if (result == DialogResult.OK)
            {
                // Authentication completed successfully
                authManager.Config.Log("LaunchingForm: Authentication completed successfully");
                MessageBox.Show(
                    "Authentication completed successfully. You can now return to the application.",
                    "Authentication Complete",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                this.DialogResult = DialogResult.OK;
                this.Close();
            }
            else
            {
                // Authentication failed or was cancelled
                authManager.Config.Log("LaunchingForm: Authentication failed or was cancelled");
                MessageBox.Show(
                    "Authentication was not completed. Please try again.",
                    "Authentication Incomplete",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                this.DialogResult = DialogResult.Cancel;
                this.Close();
            }
        }

        // Event handlers for form controls (these would be connected in the designer)
        private void btnLaunch_Click(object sender, EventArgs e)
        {
            // Allow user to skip the wait and proceed immediately
            if (displayTimer != null && displayTimer.Enabled)
            {
                displayTimer.Stop();
                authManager.Config.Log("LaunchingForm: User skipped wait time");
            }
            StartAuthenticationFlow();
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            // Cancel the authentication process
            if (displayTimer != null && displayTimer.Enabled)
            {
                displayTimer.Stop();
            }
            this.DialogResult = DialogResult.Cancel;
            this.Close();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (displayTimer != null)
                {
                    displayTimer.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }
}