using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using Rust9xWindowsAuth;
using System.Threading;

namespace HandlerGui
{
    public partial class InstallingForm : Form
    {
        private BackgroundWorker authWorker;
        private AuthManager authManager;
        private string applicationName = "WindowsApplication1";
        private string publisher = "Unknown Publisher";
        private CredentialContainer providedCredentials;
        private bool credentialsRetrievedFromManager;

        // UI Control references (these should be defined in the designer)
        // private ProgressBar progressBar;
        // private Label lblStatus;
        // private Label lblName;
        // private Label lblPublisher;
        // private Button btnCancel;

        public InstallingForm()
        {
            InitializeComponent();
            InitializeAuthWorker();
            InitializeForm();
        }

        public InstallingForm(string appName, string pubName) : this()
        {
            applicationName = appName;
            publisher = pubName;
        }

        private void InitializeForm()
        {
            // Update form UI with application info
            // This would typically update labels and progress bars
            UpdateApplicationInfo();
            
            // Initialize credential tracking
            providedCredentials = null;
            credentialsRetrievedFromManager = false;
        }

        private void UpdateApplicationInfo()
        {
            // Update labels with application information
            // This would typically update the form's UI elements
            // Using reflection to safely access controls that may not exist
            try
            {
                Control lblName = this.Controls.Find("lblName", true).Length > 0 ? 
                    this.Controls.Find("lblName", true)[0] : null;
                Control lblPublisher = this.Controls.Find("lblPublisher", true).Length > 0 ? 
                    this.Controls.Find("lblPublisher", true)[0] : null;

                if (lblName != null && lblName is Label)
                {
                    ((Label)lblName).Text = applicationName;
                }
                if (lblPublisher != null && lblPublisher is Label)
                {
                    ((Label)lblPublisher).Text = publisher;
                }
            }
            catch
            {
                // Controls may not exist, ignore errors
            }

            // Log the information
            if (authManager != null)
            {
                authManager.Config.Log("InstallingForm: Application=" + applicationName + 
                                     ", Publisher=" + publisher);
            }
        }

        private void InitializeAuthWorker()
        {
            authWorker = new BackgroundWorker();
            authWorker.DoWork += new DoWorkEventHandler(AuthWorker_DoWork);
            authWorker.RunWorkerCompleted += new RunWorkerCompletedEventHandler(AuthWorker_RunWorkerCompleted);
            authWorker.WorkerReportsProgress = true;
            authWorker.WorkerSupportsCancellation = true;
            authWorker.ProgressChanged += new ProgressChangedEventHandler(AuthWorker_ProgressChanged);
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            
            // Initialize AuthManager with current configuration
            authManager = Program.AuthManager;
            
            if (authManager == null)
            {
                MessageBox.Show(
                    "Authentication manager not available.",
                    "Authentication Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                DialogResult = DialogResult.Cancel;
                Close();
                return;
            }

            // Check if credentials were provided by ConfirmForm
            if (CredentialManager.Instance.HasCredentials)
            {
                authManager.Config.Log("InstallingForm: Credentials available from CredentialManager");
                try
                {
                    providedCredentials = CredentialManager.Instance.RetrieveAndClearCredentials();
                    credentialsRetrievedFromManager = (providedCredentials != null);
                    
                    if (credentialsRetrievedFromManager)
                    {
                        authManager.Config.Log("InstallingForm: Successfully retrieved credentials from CredentialManager");
                    }
                    else
                    {
                        authManager.Config.Log("InstallingForm: Failed to retrieve credentials from CredentialManager");
                    }
                }
                catch (Exception ex)
                {
                    authManager.Config.Log("InstallingForm: Exception retrieving credentials: " + ex.Message);
                    credentialsRetrievedFromManager = false;
                }
            }
            else
            {
                authManager.Config.Log("InstallingForm: No credentials available from CredentialManager");
            }

            // Start authentication process when form loads
            authWorker.RunWorkerAsync();
        }

        private void AuthWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                authManager.Config.Log("InstallingForm: Starting authentication process");

                // Initialize the authentication library
                authWorker.ReportProgress(5, "Initializing authentication library...");
                
                if (!authManager.Initialize())
                {
                    e.Result = "Failed to initialize authentication library";
                    return;
                }

                authWorker.ReportProgress(15, "Authentication library initialized");

                // Use provided credentials if available, otherwise authenticate normally
                CredentialContainer credentialsToUse = null;
                
                if (credentialsRetrievedFromManager && providedCredentials != null && providedCredentials.IsValid)
                {
                    authWorker.ReportProgress(20, "Using provided credentials...");
                    credentialsToUse = providedCredentials;
                    authManager.Config.Log("InstallingForm: Using credentials provided by ConfirmForm");
                }
                else
                {
                    authManager.Config.Log("InstallingForm: No valid credentials provided, will authenticate normally");
                }

                // Perform authentication with automatic retry logic
                authWorker.ReportProgress(25, "Authenticating with server...");
                
                AuthResult authResult;
                if (credentialsToUse != null)
                {
                    // Use the overload that accepts credentials
                    authResult = authManager.Authenticate(credentialsToUse);
                }
                else
                {
                    // Use normal authentication (may prompt if configured)
                    authResult = authManager.Authenticate();
                }

                if (authResult.ErrorCode != AuthErrorCode.Success)
                {
                    e.Result = "Authentication failed: " + authResult.ErrorMessage;
                    return;
                }

                authWorker.ReportProgress(75, "Authentication successful");

                // Process response if available
                if (authResult.ResponseData != null && authResult.ResponseData.Length > 0)
                {
                    authWorker.ReportProgress(85, "Processing authentication response...");
                    
                    // In a real implementation, you would process the response data
                    // For example, validate tokens, extract user info, etc.
                    string response = System.Text.Encoding.UTF8.GetString(authResult.ResponseData);
                    authManager.Config.Log("Server response: " + response);
                }

                authWorker.ReportProgress(95, "Finalizing authentication...");

                // Simulate final processing steps
                Thread.Sleep(500);

                authWorker.ReportProgress(100, "Authentication completed successfully");
                e.Result = "Authentication completed successfully";
                
                authManager.Config.Log("InstallingForm: Authentication process completed successfully");
            }
            catch (Exception ex)
            {
                e.Result = "Authentication error: " + ex.Message;
                if (authManager != null)
                {
                    authManager.Config.Log("InstallingForm: Exception during authentication: " + ex.ToString());
                }
            }
            finally
            {
                // Clean up credentials after use
                if (providedCredentials != null)
                {
                    try
                    {
                        providedCredentials.Clear();
                        providedCredentials.Dispose();
                        providedCredentials = null;
                        authManager.Config.Log("InstallingForm: Credentials cleared after use");
                    }
                    catch (Exception cleanupEx)
                    {
                        authManager.Config.Log("InstallingForm: Error clearing credentials: " + cleanupEx.Message);
                    }
                }
            }
        }

        private void AuthWorker_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            // Update progress bar and status label
            try
            {
                Control[] progressBars = this.Controls.Find("progressBar", true);
                if (progressBars.Length > 0 && progressBars[0] is ProgressBar)
                {
                    ((ProgressBar)progressBars[0]).Value = e.ProgressPercentage;
                }
                
                Control[] statusLabels = this.Controls.Find("lblStatus", true);
                if (statusLabels.Length > 0 && statusLabels[0] is Label)
                {
                    ((Label)statusLabels[0]).Text = e.UserState as string;
                }
            }
            catch
            {
                // Controls may not exist, ignore errors
            }
        }

        private void AuthWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Cancelled)
            {
                authManager.Config.Log("InstallingForm: Authentication cancelled by user");
                DialogResult = DialogResult.Cancel;
                Close();
            }
            else if (e.Error != null)
            {
                authManager.Config.Log("InstallingForm: Authentication error: " + e.Error.Message);
                MessageBox.Show(
                    "Error during authentication: " + e.Error.Message,
                    "Authentication Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                DialogResult = DialogResult.Cancel;
                Close();
            }
            else
            {
                string result = e.Result as string;
                if (result != null)
                {
                    authManager.Config.Log("InstallingForm: Authentication result: " + result);
                    
                    // Check if authentication was successful
                    if (result.IndexOf("successfully") >= 0)
                    {
                        // Success - don't show message box, just close with OK
                        DialogResult = DialogResult.OK;
                        Close();
                    }
                    else
                    {
                        // Failure - show error message
                        MessageBox.Show(
                            result,
                            "Authentication Failed",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                        DialogResult = DialogResult.Cancel;
                        Close();
                    }
                }
                else
                {
                    // No result - treat as failure
                    authManager.Config.Log("InstallingForm: No authentication result received");
                    DialogResult = DialogResult.Cancel;
                    Close();
                }
            }
        }

        private void btnCancel_Click(object sender, EventArgs e)
        {
            // Cancel the authentication process
            if (authWorker != null && authWorker.IsBusy)
            {
                authWorker.CancelAsync();
                authManager.Config.Log("InstallingForm: User requested cancellation");
            }
            else
            {
                DialogResult = DialogResult.Cancel;
                Close();
            }
        }

        private void lblName_Click(object sender, EventArgs e)
        {

        }

        private void lblFromCaption_Click(object sender, EventArgs e)
        {

        }

        private void lblNameCaption_Click(object sender, EventArgs e)
        {

        }

        private void lblFrom_Click(object sender, EventArgs e)
        {

        }

        private void whitePanel_Paint(object sender, PaintEventArgs e)
        {

        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (authWorker != null)
                {
                    authWorker.Dispose();
                }
                
                // Clean up credentials if still present
                if (providedCredentials != null)
                {
                    try
                    {
                        providedCredentials.Clear();
                        providedCredentials.Dispose();
                    }
                    catch
                    {
                        // Ignore cleanup errors
                    }
                }
                
                // Don't dispose authManager here as it's managed by Program
            }
            base.Dispose(disposing);
        }
    }
}