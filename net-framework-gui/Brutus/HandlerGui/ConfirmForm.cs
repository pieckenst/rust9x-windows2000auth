using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace HandlerGui
{
    public partial class ConfirmForm : Form
    {
        public ConfirmForm()
        {
            InitializeComponent();

            // Example values — replace with your own data
            lblNameValue.Text = "WindowsApplication1";
            lblFromValue.Text = "vbts7";
            lblPublisherValue.Text = "Unknown Publisher";

            linkMoreInformation.LinkClicked += linkMoreInformation_LinkClicked;
        }

        private void btnInstall_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.OK;
            Close();
        }

        private void btnDontInstall_Click(object sender, EventArgs e)
        {
            DialogResult = DialogResult.Cancel;
            Close();
        }

        private void linkMoreInformation_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
        {
            MessageBox.Show(
                "More information would normally open here.",
                "More Information",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void panelHeader_Paint(object sender, PaintEventArgs e)
        {

        }
    }
}