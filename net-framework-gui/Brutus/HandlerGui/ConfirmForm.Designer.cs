using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace HandlerGui
{
    

    partial class ConfirmForm
    {
        private System.ComponentModel.IContainer components = null;

        private Panel panelMain;
        private Panel panelBottom;
        private Panel panelHeader;
        private Panel panelDetails;

        private Label lblTitle;
        private Label lblQuestion;

        private Label lblNameCaption;
        private Label lblFromCaption;
        private Label lblPublisherCaption;

        private Label lblNameValue;
        private Label lblFromValue;
        private Label lblPublisherValue;

        private PictureBox pictureRight;
        private PictureBox pictureShield;

        private LinkLabel linkMoreInformation;

        private Button btnInstall;
        private Button btnDontInstall;

        private Label separatorTop;
        private Label separatorBottom;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ConfirmForm));
            this.panelMain = new System.Windows.Forms.Panel();
            this.panelDetails = new System.Windows.Forms.Panel();
            this.pictureShield = new System.Windows.Forms.PictureBox();
            this.lblNameCaption = new System.Windows.Forms.Label();
            this.lblFromCaption = new System.Windows.Forms.Label();
            this.lblPublisherCaption = new System.Windows.Forms.Label();
            this.lblNameValue = new System.Windows.Forms.Label();
            this.lblFromValue = new System.Windows.Forms.Label();
            this.lblPublisherValue = new System.Windows.Forms.Label();
            this.linkMoreInformation = new System.Windows.Forms.LinkLabel();
            this.panelHeader = new System.Windows.Forms.Panel();
            this.pictureRight = new System.Windows.Forms.PictureBox();
            this.lblTitle = new System.Windows.Forms.Label();
            this.lblQuestion = new System.Windows.Forms.Label();
            this.separatorBottom = new System.Windows.Forms.Label();
            this.panelBottom = new System.Windows.Forms.Panel();
            this.btnInstall = new System.Windows.Forms.Button();
            this.btnDontInstall = new System.Windows.Forms.Button();
            this.separatorTop = new System.Windows.Forms.Label();
            this.panelMain.SuspendLayout();
            this.panelDetails.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureShield)).BeginInit();
            this.panelHeader.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureRight)).BeginInit();
            this.panelBottom.SuspendLayout();
            this.SuspendLayout();
            // 
            // panelMain
            // 
            this.panelMain.BackColor = System.Drawing.SystemColors.Control;
            this.panelMain.Controls.Add(this.panelDetails);
            this.panelMain.Controls.Add(this.panelHeader);
            this.panelMain.Controls.Add(this.separatorBottom);
            this.panelMain.Controls.Add(this.panelBottom);
            this.panelMain.Controls.Add(this.separatorTop);
            this.panelMain.Location = new System.Drawing.Point(0, 0);
            this.panelMain.Name = "panelMain";
            this.panelMain.Size = new System.Drawing.Size(508, 322);
            this.panelMain.TabIndex = 0;
            // 
            // panelDetails
            // 
            this.panelDetails.BackColor = System.Drawing.Color.Beige;
            this.panelDetails.Controls.Add(this.pictureShield);
            this.panelDetails.Controls.Add(this.lblNameCaption);
            this.panelDetails.Controls.Add(this.lblFromCaption);
            this.panelDetails.Controls.Add(this.lblPublisherCaption);
            this.panelDetails.Controls.Add(this.lblNameValue);
            this.panelDetails.Controls.Add(this.lblFromValue);
            this.panelDetails.Controls.Add(this.lblPublisherValue);
            this.panelDetails.Controls.Add(this.linkMoreInformation);
            this.panelDetails.Dock = System.Windows.Forms.DockStyle.Top;
            this.panelDetails.Location = new System.Drawing.Point(0, 74);
            this.panelDetails.Name = "panelDetails";
            this.panelDetails.Padding = new System.Windows.Forms.Padding(18, 10, 18, 0);
            this.panelDetails.Size = new System.Drawing.Size(508, 179);
            this.panelDetails.TabIndex = 0;
            // 
            // pictureShield
            // 
            this.pictureShield.Image = ((System.Drawing.Image)(resources.GetObject("pictureShield.Image")));
            this.pictureShield.Location = new System.Drawing.Point(32, 27);
            this.pictureShield.Name = "pictureShield";
            this.pictureShield.Size = new System.Drawing.Size(43, 82);
            this.pictureShield.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureShield.TabIndex = 0;
            this.pictureShield.TabStop = false;
            // 
            // lblNameCaption
            // 
            this.lblNameCaption.AutoSize = true;
            this.lblNameCaption.Location = new System.Drawing.Point(92, 36);
            this.lblNameCaption.Name = "lblNameCaption";
            this.lblNameCaption.Size = new System.Drawing.Size(38, 13);
            this.lblNameCaption.TabIndex = 1;
            this.lblNameCaption.Text = "Name:";
            // 
            // lblFromCaption
            // 
            this.lblFromCaption.AutoSize = true;
            this.lblFromCaption.Location = new System.Drawing.Point(92, 58);
            this.lblFromCaption.Name = "lblFromCaption";
            this.lblFromCaption.Size = new System.Drawing.Size(35, 13);
            this.lblFromCaption.TabIndex = 2;
            this.lblFromCaption.Text = "From:";
            // 
            // lblPublisherCaption
            // 
            this.lblPublisherCaption.AutoSize = true;
            this.lblPublisherCaption.Location = new System.Drawing.Point(92, 80);
            this.lblPublisherCaption.Name = "lblPublisherCaption";
            this.lblPublisherCaption.Size = new System.Drawing.Size(54, 13);
            this.lblPublisherCaption.TabIndex = 3;
            this.lblPublisherCaption.Text = "Publisher:";
            // 
            // lblNameValue
            // 
            this.lblNameValue.AutoSize = true;
            this.lblNameValue.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold);
            this.lblNameValue.Location = new System.Drawing.Point(160, 36);
            this.lblNameValue.Name = "lblNameValue";
            this.lblNameValue.Size = new System.Drawing.Size(79, 13);
            this.lblNameValue.TabIndex = 4;
            this.lblNameValue.Text = "WindowsApp";
            // 
            // lblFromValue
            // 
            this.lblFromValue.AutoSize = true;
            this.lblFromValue.Location = new System.Drawing.Point(160, 58);
            this.lblFromValue.Name = "lblFromValue";
            this.lblFromValue.Size = new System.Drawing.Size(20, 13);
            this.lblFromValue.TabIndex = 5;
            this.lblFromValue.Text = "Url";
            // 
            // lblPublisherValue
            // 
            this.lblPublisherValue.AutoSize = true;
            this.lblPublisherValue.Location = new System.Drawing.Point(160, 80);
            this.lblPublisherValue.Name = "lblPublisherValue";
            this.lblPublisherValue.Size = new System.Drawing.Size(97, 13);
            this.lblPublisherValue.TabIndex = 6;
            this.lblPublisherValue.Text = "Unknown Publisher";
            // 
            // linkMoreInformation
            // 
            this.linkMoreInformation.AutoSize = true;
            this.linkMoreInformation.Location = new System.Drawing.Point(92, 107);
            this.linkMoreInformation.Name = "linkMoreInformation";
            this.linkMoreInformation.Size = new System.Drawing.Size(102, 13);
            this.linkMoreInformation.TabIndex = 7;
            this.linkMoreInformation.TabStop = true;
            this.linkMoreInformation.Text = "More Information...";
            // 
            // panelHeader
            // 
            this.panelHeader.BackColor = System.Drawing.Color.WhiteSmoke;
            this.panelHeader.Controls.Add(this.pictureRight);
            this.panelHeader.Controls.Add(this.lblTitle);
            this.panelHeader.Controls.Add(this.lblQuestion);
            this.panelHeader.Dock = System.Windows.Forms.DockStyle.Top;
            this.panelHeader.Location = new System.Drawing.Point(0, 4);
            this.panelHeader.Name = "panelHeader";
            this.panelHeader.Padding = new System.Windows.Forms.Padding(18, 18, 18, 0);
            this.panelHeader.Size = new System.Drawing.Size(508, 70);
            this.panelHeader.TabIndex = 1;
            this.panelHeader.Paint += new System.Windows.Forms.PaintEventHandler(this.panelHeader_Paint);
            // 
            // pictureRight
            // 
            this.pictureRight.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.pictureRight.Image = ((System.Drawing.Image)(resources.GetObject("pictureRight.Image")));
            this.pictureRight.Location = new System.Drawing.Point(732, 10);
            this.pictureRight.Name = "pictureRight";
            this.pictureRight.Size = new System.Drawing.Size(48, 48);
            this.pictureRight.SizeMode = System.Windows.Forms.PictureBoxSizeMode.CenterImage;
            this.pictureRight.TabIndex = 0;
            this.pictureRight.TabStop = false;
            // 
            // lblTitle
            // 
            this.lblTitle.AutoSize = true;
            this.lblTitle.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold);
            this.lblTitle.Location = new System.Drawing.Point(18, 18);
            this.lblTitle.Name = "lblTitle";
            this.lblTitle.Size = new System.Drawing.Size(152, 13);
            this.lblTitle.TabIndex = 1;
            this.lblTitle.Text = "This will open a login form";
            // 
            // lblQuestion
            // 
            this.lblQuestion.AutoSize = true;
            this.lblQuestion.Font = new System.Drawing.Font("Tahoma", 8.25F);
            this.lblQuestion.Location = new System.Drawing.Point(18, 40);
            this.lblQuestion.Name = "lblQuestion";
            this.lblQuestion.Size = new System.Drawing.Size(177, 13);
            this.lblQuestion.TabIndex = 2;
            this.lblQuestion.Text = "Are you sure you want to proceed?";
            // 
            // separatorBottom
            // 
            this.separatorBottom.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.separatorBottom.Dock = System.Windows.Forms.DockStyle.Top;
            this.separatorBottom.Location = new System.Drawing.Point(0, 2);
            this.separatorBottom.Margin = new System.Windows.Forms.Padding(0);
            this.separatorBottom.Name = "separatorBottom";
            this.separatorBottom.Size = new System.Drawing.Size(508, 2);
            this.separatorBottom.TabIndex = 2;
            // 
            // panelBottom
            // 
            this.panelBottom.BackColor = System.Drawing.SystemColors.Control;
            this.panelBottom.Controls.Add(this.btnInstall);
            this.panelBottom.Controls.Add(this.btnDontInstall);
            this.panelBottom.Dock = System.Windows.Forms.DockStyle.Fill;
            this.panelBottom.Location = new System.Drawing.Point(0, 2);
            this.panelBottom.Name = "panelBottom";
            this.panelBottom.Padding = new System.Windows.Forms.Padding(0, 12, 18, 12);
            this.panelBottom.Size = new System.Drawing.Size(508, 320);
            this.panelBottom.TabIndex = 3;
            // 
            // btnInstall
            // 
            this.btnInstall.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnInstall.Location = new System.Drawing.Point(310, 270);
            this.btnInstall.Name = "btnInstall";
            this.btnInstall.Size = new System.Drawing.Size(88, 26);
            this.btnInstall.TabIndex = 0;
            this.btnInstall.Text = "Proceed";
            this.btnInstall.UseVisualStyleBackColor = true;
            this.btnInstall.Click += new System.EventHandler(this.btnInstall_Click);
            // 
            // btnDontInstall
            // 
            this.btnDontInstall.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnDontInstall.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnDontInstall.Location = new System.Drawing.Point(408, 270);
            this.btnDontInstall.Name = "btnDontInstall";
            this.btnDontInstall.Size = new System.Drawing.Size(88, 26);
            this.btnDontInstall.TabIndex = 1;
            this.btnDontInstall.Text = "Cancel";
            this.btnDontInstall.UseVisualStyleBackColor = true;
            this.btnDontInstall.Click += new System.EventHandler(this.btnDontInstall_Click);
            // 
            // separatorTop
            // 
            this.separatorTop.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.separatorTop.Dock = System.Windows.Forms.DockStyle.Top;
            this.separatorTop.Location = new System.Drawing.Point(0, 0);
            this.separatorTop.Margin = new System.Windows.Forms.Padding(0);
            this.separatorTop.Name = "separatorTop";
            this.separatorTop.Size = new System.Drawing.Size(508, 2);
            this.separatorTop.TabIndex = 4;
            // 
            // ConfirmForm
            // 
            this.AcceptButton = this.btnInstall;
            this.BackColor = System.Drawing.SystemColors.Control;
            this.CancelButton = this.btnDontInstall;
            this.ClientSize = new System.Drawing.Size(508, 322);
            this.Controls.Add(this.panelMain);
            this.Font = new System.Drawing.Font("Tahoma", 8.25F);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "ConfirmForm";
            this.ShowInTaskbar = false;
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Hide;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Confirmation";
            this.panelMain.ResumeLayout(false);
            this.panelDetails.ResumeLayout(false);
            this.panelDetails.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureShield)).EndInit();
            this.panelHeader.ResumeLayout(false);
            this.panelHeader.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureRight)).EndInit();
            this.panelBottom.ResumeLayout(false);
            this.ResumeLayout(false);

        }
    }
}