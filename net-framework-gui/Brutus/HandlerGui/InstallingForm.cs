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
            // This would typically be set via properties or constructor
        }

        private void InitializeAuthWorker()
        {
            authWorker = new BackgroundWorker();
            authWorker.DoWork += AuthWorker_DoWork;
            authWorker.RunWorkerCompleted += AuthWorker_RunWorkerCompleted;
            authWorker.WorkerReportsProgress = true;
            authWorker.WorkerSupportsCancellation = true;
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            
            // Initialize AuthManager with current configuration
            authManager = new AuthManager();
            
            // Start authentication process when form loads
            authWorker.RunWorkerAsync();
        }

        private void AuthWorker_DoWork(object sender, DoWorkEventArgs e)
        {
            try
            {
                // Initialize the authentication library
                authWorker.ReportProgress(10, "Initializing authentication library...");
                
                if (!authManager.Initialize())
                {
                    e.Result = "Failed to initialize authentication library";
                    return;
                }

                authWorker.ReportProgress(20, "Authentication library initialized");

                // Perform authentication with automatic retry logic
                authWorker.ReportProgress(30, "Authenticating with server...");
                
                AuthResult authResult = authManager.Authenticate();

                if (authResult.ErrorCode != AuthErrorCode.Success)
                {
                    e.Result = "Authentication failed: " + authResult.ErrorMessage;
                    return;
                }

                authWorker.ReportProgress(70, "Authentication successful");

                // Process response if available
                if (authResult.ResponseData != null && authResult.ResponseData.Length > 0)
                {
                    authWorker.ReportProgress(80, "Processing authentication response...");
                    
                    // In a real implementation, you would process the response data
                    // For example, validate tokens, extract user info, etc.
                    string response = System.Text.Encoding.UTF8.GetString(authResult.ResponseData);
                    authManager.Config.Log("Server response: " + response);
                }

                authWorker.ReportProgress(90, "Finalizing authentication...");

                // Simulate final processing steps
                Thread.Sleep(500);

                authWorker.ReportProgress(100, "Authentication completed successfully");
                e.Result = "Authentication completed successfully";
            }
            catch (Exception ex)
            {
                e.Result = "Authentication error: " + ex.Message;
                if (authManager != null)
                {
                    authManager.Config.Log("Exception during authentication: " + ex.ToString());
                }
            }
        }

        private void AuthWorker_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            if (e.Cancelled)
            {
                DialogResult = DialogResult.Cancel;
                Close();
            }
            else if (e.Error != null)
            {
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
                    // Show success message
                    MessageBox.Show(
                        result,
                        "Authentication Complete",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
                DialogResult = DialogResult.OK;
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
                if (authManager != null)
                {
                    authManager.Dispose();
                }
            }
            base.Dispose(disposing);
        }
    }
}