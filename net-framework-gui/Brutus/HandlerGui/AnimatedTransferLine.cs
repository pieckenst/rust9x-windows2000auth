using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace HandlerGui
{
    public class AnimatedTransferLine : Control
    {
        private Timer timer;
        private int offset = -30;
        private Color backgroundLineColor = Color.Silver;
        private Color segmentColor = Color.FromArgb(120, 205, 85);
        private int segmentWidth = 28;
        private int speed = 2;

        public Color BackgroundLineColor
        {
            get { return backgroundLineColor; }
            set { backgroundLineColor = value; }
        }

        public Color SegmentColor
        {
            get { return segmentColor; }
            set { segmentColor = value; }
        }

        public int SegmentWidth
        {
            get { return segmentWidth; }
            set { segmentWidth = value; }
        }

        public int Speed
        {
            get { return speed; }
            set { speed = value; }
        }

        public AnimatedTransferLine()
        {
            timer = new Timer();
            DoubleBuffered = true;
            Height = 8;

            timer.Interval = 16;
            timer.Tick += new EventHandler(Timer_Tick);
            timer.Start();
        }

        private void Timer_Tick(object sender, EventArgs e)
        {
            offset += speed;

            if (offset > Width)
                offset = -segmentWidth;

            Invalidate();
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            Graphics g = e.Graphics;

            int y = Height / 2;

            Pen gray = new Pen(backgroundLineColor);
            try
            {
                g.DrawLine(gray, 0, y, Width, y);
            }
            finally
            {
                gray.Dispose();
            }

            LinearGradientBrush brush = new LinearGradientBrush(
                new Rectangle(offset, y - 1, segmentWidth, 3),
                Color.FromArgb(235, 255, 235),
                Color.FromArgb(60, 175, 55),
                LinearGradientMode.Horizontal);
            try
            {
                Pen p = new Pen(brush, 2);
                try
                {
                    g.DrawLine(p, offset, y, offset + segmentWidth, y);
                }
                finally
                {
                    p.Dispose();
                }
            }
            finally
            {
                brush.Dispose();
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                if (timer != null)
                {
                    timer.Stop();
                    timer.Dispose();
                    timer = null;
                }
            }
            base.Dispose(disposing);
        }
    }
}
