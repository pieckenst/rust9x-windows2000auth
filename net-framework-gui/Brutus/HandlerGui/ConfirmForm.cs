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
    public partial class ConfirmForm : Form
    {
        private AuthManager authManager;
        private string applicationName;
        private string publisher;
        private string requestedUrl;

        public ConfirmForm()
        {
            InitializeComponent();
            InitializeForm();
        }

        public ConfirmForm(string appName, string pubName, string url) : this()
        {
            applicationName = appName;
            publisher = pubName;
            requestedUrl = url;
        }

        private void InitializeForm()
        {
            // Get the global auth manager from Program
            authManager = Program.AuthManager;

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

            // Update UI with application information
            UpdateApplicationInfo();

            // Wire up event handlers
            linkMoreInformation.LinkClicked += new LinkLabelLinkClickedEventHandler(linkMoreInformation_LinkClicked);
        }

        private void UpdateApplicationInfo()
        {
            // Update labels with application information
            // This would typically update the form's UI elements
            if (lblNameValue != null)
            {
                lblNameValue.Text = applicationName;
            }
            if (lblFromValue != null)
            {
                lblFromValue.Text = GetUrlDomain(requestedUrl);
            }
            if (lblPublisherValue != null)
            {
                lblPublisherValue.Text = publisher;
            }

            // Log the information
            if (authManager != null)
            {
                authManager.Config.Log("ConfirmForm: Application=" + applicationName + 
                                     ", Publisher=" + publisher + 
                                     ", URL=" + requestedUrl);
            }
        }

        private string GetUrlDomain(string url)
        {
            try
            {
                if (string.IsNullOrEmpty(url))
                {
                    return "Unknown";
                }

                Uri uri = new Uri(url);
                return uri.Host;
            }
            catch
            {
                return "Unknown";
            }
        }

        private void btnInstall_Click(object sender, EventArgs e)
        {
            // User confirmed - prompt for credentials before proceeding
            PromptForCredentials();
        }

        private void btnDontInstall_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private void PromptForCredentials()
        {
            try
            {
                if (authManager == null)
                {
                    MessageBox.Show(
                        "Authentication manager not available.",
                        "Authentication Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                authManager.Config.Log("ConfirmForm: Prompting for Windows credentials");

                // Use the AuthManager to prompt for credentials via Windows dialog
                AuthResult promptResult = authManager.PromptForCredentials();

                if (promptResult.ErrorCode == AuthErrorCode.Success)
                {
                    authManager.Config.Log("ConfirmForm: Credentials provided successfully");
                    DialogResult = DialogResult.OK;
                    Close();
                }
                else
                {
                    authManager.Config.Log("ConfirmForm: Credential prompt failed: " + promptResult.ErrorMessage);
                    MessageBox.Show(
                        "Failed to obtain credentials: " + promptResult.ErrorMessage,
                        "Credential Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                if (authManager != null)
                {
                    authManager.Config.Log("EXCEPTION TYPE: " + ex.GetType().FullName);
                    authManager.Config.Log("MESSAGE: " + ex.Message);
                    authManager.Config.Log("STACK TRACE:\r\n" + ex.StackTrace);
                    
                    if (ex.InnerException != null)
                    {
                        authManager.Config.Log("INNER TYPE: " + ex.InnerException.GetType().FullName);
                        authManager.Config.Log("INNER MESSAGE: " + ex.InnerException.Message);
                        authManager.Config.Log("INNER STACK:\r\n" + ex.InnerException.StackTrace);
                    }
                    
                    authManager.Config.Log("ConfirmForm: Error prompting for credentials: " + ex.Message);
                }
                MessageBox.Show(
                    "Error prompting for credentials: " + ex.Message,
                    "Credential Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void linkMoreInformation_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            // Show more information about the authentication request
            StringBuilder info = new StringBuilder();
            info.AppendLine("Authentication Request Details:");
            info.AppendLine();
            info.AppendLine("Application: " + applicationName);
            info.AppendLine("Publisher: " + publisher);
            info.AppendLine("Target URL: " + requestedUrl);
            info.AppendLine();
            info.AppendLine("This application is requesting Windows authentication");
            info.AppendLine("to access resources on your behalf.");

            MessageBox.Show(
                info.ToString(),
                "Authentication Information",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void panelHeader_Paint(object sender, PaintEventArgs e)
        {

        }
    }
}