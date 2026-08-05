using System.Drawing;
using System.Windows.Forms;

namespace HandlerGui
{
    public partial class LaunchingForm : Form
    {
        PictureBox pictureComputer;
        PictureBox pictureGlobe;

        Panel whitePanel;

        AnimatedTransferLine transferLine;

        Label lblStatus;

         

        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(LaunchingForm));
            this.whitePanel = new System.Windows.Forms.Panel();
            this.pictureComputer = new System.Windows.Forms.PictureBox();
            this.pictureGlobe = new System.Windows.Forms.PictureBox();
            this.transferLine = new AnimatedTransferLine();
            this.lblStatus = new System.Windows.Forms.Label();
            this.whitePanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.pictureComputer)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureGlobe)).BeginInit();
            this.SuspendLayout();
            // 
            // whitePanel
            // 
            this.whitePanel.BackColor = System.Drawing.Color.White;
            this.whitePanel.Controls.Add(this.pictureComputer);
            this.whitePanel.Controls.Add(this.pictureGlobe);
            this.whitePanel.Controls.Add(this.transferLine);
            this.whitePanel.Controls.Add(this.lblStatus);
            this.whitePanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.whitePanel.Location = new System.Drawing.Point(0, 0);
            this.whitePanel.Name = "whitePanel";
            this.whitePanel.Size = new System.Drawing.Size(388, 111);
            this.whitePanel.TabIndex = 0;
            // 
            // pictureComputer
            // 
            this.pictureComputer.Image = ((System.Drawing.Image)(resources.GetObject("pictureComputer.Image")));
            this.pictureComputer.Location = new System.Drawing.Point(28, 28);
            this.pictureComputer.Name = "pictureComputer";
            this.pictureComputer.Size = new System.Drawing.Size(32, 32);
            this.pictureComputer.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureComputer.TabIndex = 0;
            this.pictureComputer.TabStop = false;
            // 
            // pictureGlobe
            // 
            this.pictureGlobe.Image = ((System.Drawing.Image)(resources.GetObject("pictureGlobe.Image")));
            this.pictureGlobe.Location = new System.Drawing.Point(317, 28);
            this.pictureGlobe.Name = "pictureGlobe";
            this.pictureGlobe.Size = new System.Drawing.Size(32, 32);
            this.pictureGlobe.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.pictureGlobe.TabIndex = 1;
            this.pictureGlobe.TabStop = false;
            // 
            // transferLine
            // 
            this.transferLine.Location = new System.Drawing.Point(62, 40);
            this.transferLine.Name = "transferLine";
            this.transferLine.Size = new System.Drawing.Size(270, 8);
            this.transferLine.TabIndex = 2;
            // 
            // lblStatus
            // 
            this.lblStatus.Location = new System.Drawing.Point(30, 70);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(319, 32);
            this.lblStatus.TabIndex = 3;
            this.lblStatus.Text = "Verifying application requirements. This may take a few moments.";
            // 
            // LaunchingForm
            // 
            this.BackColor = System.Drawing.SystemColors.Control;
            this.ClientSize = new System.Drawing.Size(388, 111);
            this.Controls.Add(this.whitePanel);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "LaunchingForm";
            this.ShowIcon = false;
            this.ShowInTaskbar = false;
            this.SizeGripStyle = System.Windows.Forms.SizeGripStyle.Hide;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Launching Application";
            this.whitePanel.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.pictureComputer)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.pictureGlobe)).EndInit();
            this.ResumeLayout(false);

        }

        public void SetStatus(string text)
        {
            lblStatus.Text = text;
        }
    }
}