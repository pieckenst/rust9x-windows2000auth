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
        private bool isPromptingForCredentials;
        private FormWindowState previousWindowState;

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
            isPromptingForCredentials = false;
            previousWindowState = FormWindowState.Normal;

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

                authManager.Config.Log("ConfirmForm: Starting credential collection process");
                isPromptingForCredentials = true;

                // Hide the ConfirmForm UI to show only the Windows credentials dialog
                HideFormForCredentialPrompt();

                authManager.Config.Log("ConfirmForm: Prompting for Windows credentials");

                // Use the AuthManager to prompt for credentials via Windows dialog
                AuthResult promptResult = authManager.PromptForCredentials();

                if (promptResult.ErrorCode == AuthErrorCode.Success)
                {
                    authManager.Config.Log("ConfirmForm: Credentials provided successfully");
                    
                    // Store credentials in CredentialManager for secure passing to InstallingForm
                    try
                    {
                        CredentialContainer credentials = CreateCredentialContainerFromAuthResult(promptResult);
                        if (credentials != null && credentials.HasCredentials())
                        {
                            CredentialManager.Instance.StoreCredentials(credentials, 120000); // 2 minutes
                            authManager.Config.Log("ConfirmForm: Credentials stored securely in CredentialManager");
                            
                            // Show form briefly before proceeding
                            ShowFormAfterCredentialPrompt();
                            
                            DialogResult = DialogResult.OK;
                            Close();
                        }
                        else
                        {
                            authManager.Config.Log("ConfirmForm: Failed to create valid credential container");
                            ShowFormAfterCredentialPrompt();
                            MessageBox.Show(
                                "Failed to process credentials properly.",
                                "Credential Error",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Warning);
                        }
                    }
                    catch (Exception credEx)
                    {
                        authManager.Config.Log("ConfirmForm: Exception storing credentials: " + credEx.Message);
                        ShowFormAfterCredentialPrompt();
                        MessageBox.Show(
                            "Error processing credentials: " + credEx.Message,
                            "Credential Error",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Warning);
                    }
                }
                else
                {
                    authManager.Config.Log("ConfirmForm: Credential prompt failed: " + promptResult.ErrorMessage);
                    ShowFormAfterCredentialPrompt();
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
                ShowFormAfterCredentialPrompt();
                MessageBox.Show(
                    "Error prompting for credentials: " + ex.Message,
                    "Credential Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            finally
            {
                isPromptingForCredentials = false;
            }
        }

        /// <summary>
        /// Hide the form during credential prompt to show only the Windows credentials dialog
        /// </summary>
        private void HideFormForCredentialPrompt()
        {
            try
            {
                // Store current window state
                previousWindowState = this.WindowState;
                
                // Hide the form completely
                this.Hide();
                
                // Disable the form to prevent any interaction
                this.Enabled = false;
                
                authManager.Config.Log("ConfirmForm: Form hidden for credential prompt");
            }
            catch (Exception ex)
            {
                authManager.Config.Log("ConfirmForm: Error hiding form: " + ex.Message);
            }
        }

        /// <summary>
        /// Show the form after credential prompt is complete
        /// </summary>
        private void ShowFormAfterCredentialPrompt()
        {
            try
            {
                // Re-enable the form
                this.Enabled = true;
                
                // Show the form again
                this.Show();
                
                // Restore previous window state
                this.WindowState = previousWindowState;
                
                // Bring to front
                this.BringToFront();
                this.Activate();
                
                authManager.Config.Log("ConfirmForm: Form restored after credential prompt");
            }
            catch (Exception ex)
            {
                authManager.Config.Log("ConfirmForm: Error showing form: " + ex.Message);
            }
        }

        /// <summary>
        /// Create a CredentialContainer from the current authentication configuration
        /// This extracts credentials that were set by the credential prompt
        /// </summary>
        private CredentialContainer CreateCredentialContainerFromAuthResult(AuthResult authResult)
        {
            try
            {
                // Get credentials from the auth manager config (they were set by the prompt)
                string username = authManager.Config.Username;
                string password = authManager.Config.Password;
                string domain = authManager.Config.Domain;

                // Validate we have the necessary credentials
                if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    authManager.Config.Log("ConfirmForm: No credentials available in config after prompt");
                    return null;
                }

                // Create secure credential container
                CredentialContainer credentials = new CredentialContainer(username, password, domain);
                authManager.Config.Log("ConfirmForm: Created credential container for user: " + username);

                // Clear the credentials from config after creating container
                authManager.Config.Username = null;
                authManager.Config.Password = null;
                authManager.Config.Domain = null;

                return credentials;
            }
            catch (Exception ex)
            {
                authManager.Config.Log("ConfirmForm: Exception creating credential container: " + ex.Message);
                return null;
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

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            // Clean up credentials if form is closed during credential prompt
            if (isPromptingForCredentials)
            {
                authManager.Config.Log("ConfirmForm: Form closing during credential prompt, cleaning up");
                CredentialManager.Instance.ClearCredentials();
            }
            base.OnFormClosing(e);
        }
    }
}