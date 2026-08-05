using System;
using System.Drawing;
using System.Windows.Forms;

namespace HandlerGui
{
    public partial class InstallingForm : Form
    {
        Label lblHeader;
        Label lblDescription;

        Label lblNameCaption;
        Label lblName;

        Label lblFromCaption;
        Label lblFrom;

        Label lblDownload;

        ProgressBar progressBar;

        Button btnCancel;

        PictureBox pictureStatus;

        Panel whitePanel;
        Label sep;

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(InstallingForm));
            this.whitePanel = new System.Windows.Forms.Panel();
            this.pictureStatus = new System.Windows.Forms.PictureBox();
            this.lblHeader = new System.Windows.Forms.Label();
            this.lblDescription = new System.Windows.Forms.Label();
            this.lblNameCaption = new System.Windows.Forms.Label();
            this.lblName = new System.Windows.Forms.Label();
            this.lblFromCaption = new System.Windows.Forms.Label();
            this.lblFrom = new System.Windows.Forms.Label();
            this.progressBar = new System.Windows.Forms.ProgressBar();
            this.lblDownload = new System.Windows.Forms.Label();
            this.sep = new System.Windows.Forms.Label();
            this.btnCancel = new System.Windows.Forms.Button();
            this.pictureBox1 = new System.Windows.Forms.PictureBox();
            this.whitePanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureStatus)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).BeginInit();
            this.SuspendLayout();
            // 
            // whitePanel
            // 
            this.whitePanel.BackColor = System.Drawing.Color.White;
            this.whitePanel.Controls.Add(this.pictureBox1);
            this.whitePanel.Controls.Add(this.pictureStatus);
            this.whitePanel.Controls.Add(this.lblHeader);
            this.whitePanel.Controls.Add(this.lblDescription);
            this.whitePanel.Controls.Add(this.lblNameCaption);
            this.whitePanel.Controls.Add(this.lblName);
            this.whitePanel.Controls.Add(this.lblFromCaption);
            this.whitePanel.Controls.Add(this.lblFrom);
            this.whitePanel.Controls.Add(this.progressBar);
            this.whitePanel.Controls.Add(this.lblDownload);
            this.whitePanel.Dock = System.Windows.Forms.DockStyle.Top;
            this.whitePanel.Location = new System.Drawing.Point(0, 2);
            this.whitePanel.Name = "whitePanel";
            this.whitePanel.Size = new System.Drawing.Size(500, 199);
            this.whitePanel.TabIndex = 0;
            this.whitePanel.Paint += new System.Windows.Forms.PaintEventHandler(this.whitePanel_Paint);
            // 
            // pictureStatus
            // 
            this.pictureStatus.Image = ((System.Drawing.Image)(resources.GetObject("pictureStatus.Image")));
            this.pictureStatus.Location = new System.Drawing.Point(430, 12);
            this.pictureStatus.Name = "pictureStatus";
            this.pictureStatus.Size = new System.Drawing.Size(48, 48);
            this.pictureStatus.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureStatus.TabIndex = 0;
            this.pictureStatus.TabStop = false;
            // 
            // lblHeader
            // 
            this.lblHeader.AutoSize = true;
            this.lblHeader.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold);
            this.lblHeader.Location = new System.Drawing.Point(15, 15);
            this.lblHeader.Name = "lblHeader";
            this.lblHeader.Size = new System.Drawing.Size(68, 13);
            this.lblHeader.TabIndex = 1;
            this.lblHeader.Text = "Processing";
            // 
            // lblDescription
            // 
            this.lblDescription.Location = new System.Drawing.Point(15, 35);
            this.lblDescription.Name = "lblDescription";
            this.lblDescription.Size = new System.Drawing.Size(379, 32);
            this.lblDescription.TabIndex = 2;
            this.lblDescription.Text = "This may take several minutes. You can use your computer to do other tasks during" +
                " this work.";
            // 
            // lblNameCaption
            // 
            this.lblNameCaption.AutoSize = true;
            this.lblNameCaption.Location = new System.Drawing.Point(72, 88);
            this.lblNameCaption.Name = "lblNameCaption";
            this.lblNameCaption.Size = new System.Drawing.Size(38, 13);
            this.lblNameCaption.TabIndex = 3;
            this.lblNameCaption.Text = "Name:";
            // 
            // lblName
            // 
            this.lblName.AutoSize = true;
            this.lblName.Font = new System.Drawing.Font("Tahoma", 8.25F, System.Drawing.FontStyle.Bold);
            this.lblName.Location = new System.Drawing.Point(135, 88);
            this.lblName.Name = "lblName";
            this.lblName.Size = new System.Drawing.Size(127, 13);
            this.lblName.TabIndex = 4;
            this.lblName.Text = "WindowsApplication1";
            // 
            // lblFromCaption
            // 
            this.lblFromCaption.AutoSize = true;
            this.lblFromCaption.Location = new System.Drawing.Point(72, 108);
            this.lblFromCaption.Name = "lblFromCaption";
            this.lblFromCaption.Size = new System.Drawing.Size(33, 13);
            this.lblFromCaption.TabIndex = 5;
            this.lblFromCaption.Text = "From:";
            // 
            // lblFrom
            // 
            this.lblFrom.AutoSize = true;
            this.lblFrom.Location = new System.Drawing.Point(135, 108);
            this.lblFrom.Name = "lblFrom";
            this.lblFrom.Size = new System.Drawing.Size(33, 13);
            this.lblFrom.TabIndex = 6;
            this.lblFrom.Text = "vbts7";
            // 
            // progressBar
            // 
            this.progressBar.Location = new System.Drawing.Point(39, 148);
            this.progressBar.Name = "progressBar";
            this.progressBar.Size = new System.Drawing.Size(449, 18);
            this.progressBar.TabIndex = 7;
            // 
            // lblDownload
            // 
            this.lblDownload.AutoSize = true;
            this.lblDownload.Location = new System.Drawing.Point(36, 169);
            this.lblDownload.Name = "lblDownload";
            this.lblDownload.Size = new System.Drawing.Size(61, 13);
            this.lblDownload.TabIndex = 8;
            this.lblDownload.Text = "Please wait";
            // 
            // sep
            // 
            this.sep.BorderStyle = System.Windows.Forms.BorderStyle.Fixed3D;
            this.sep.Dock = System.Windows.Forms.DockStyle.Top;
            this.sep.Location = new System.Drawing.Point(0, 0);
            this.sep.Name = "sep";
            this.sep.Size = new System.Drawing.Size(500, 2);
            this.sep.TabIndex = 1;
            // 
            // btnCancel
            // 
            this.btnCancel.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnCancel.Location = new System.Drawing.Point(413, 208);
            this.btnCancel.Name = "btnCancel";
            this.btnCancel.Size = new System.Drawing.Size(75, 24);
            this.btnCancel.TabIndex = 2;
            this.btnCancel.Text = "Cancel";
            // 
            // pictureBox1
            // 
            this.pictureBox1.Image = ((System.Drawing.Image)(resources.GetObject("pictureBox1.Image")));
            this.pictureBox1.Location = new System.Drawing.Point(12, 88);
            this.pictureBox1.Name = "pictureBox1";
            this.pictureBox1.Size = new System.Drawing.Size(54, 33);
            this.pictureBox1.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureBox1.TabIndex = 9;
            this.pictureBox1.TabStop = false;
            // 
            // InstallingForm
            // 
            this.BackColor = System.Drawing.SystemColors.Control;
            this.ClientSize = new System.Drawing.Size(500, 244);
            this.Controls.Add(this.whitePanel);
            this.Controls.Add(this.sep);
            this.Controls.Add(this.btnCancel);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "InstallingForm";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Hide;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Application progress";
            this.whitePanel.ResumeLayout(false);
            this.whitePanel.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureStatus)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureBox1)).EndInit();
            this.ResumeLayout(false);

        }

        public void UpdateProgress(int percent, string text)
        {
            percent = Math.Max(0, Math.Min(100, percent));

            progressBar.Value = percent;
            lblDownload.Text = text;

        }

        private PictureBox pictureBox1;
    }
}