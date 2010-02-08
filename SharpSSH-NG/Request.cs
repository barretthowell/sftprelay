using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace SharpSSH.NG
{
    abstract class Request
    {
        private bool reply = false;
        private Session session = null;
        private Channel channel = null;
        internal virtual void request(Session session, Channel channel)
        {
            this.session = session;
            this.channel = channel;
            if (channel.connectTimeout > 0)
            {
                setReply(true);
            }
        }
        protected bool waitForReply() { return reply; }
        protected void setReply(bool reply) { this.reply = reply; }
        protected void write(Packet packet)
        {
            if (reply)
            {
                channel.reply = -1;
            }
            session.write(packet);
            if (reply)
            {
                long start = JavaCompat.CurrentTimeMillis();
                long timeout = channel.connectTimeout;
                while (channel.Connected && channel.reply == -1)
                {
                    try { Thread.Sleep(10); }
                    catch //(Exception ee)
                    {
                    }
                    if (timeout > 0L &&
                       (JavaCompat.CurrentTimeMillis() - start) > timeout)
                    {
                        channel.reply = 0;
                        throw new JSchException("channel request: timeout");
                    }
                }

                if (channel.reply == 0)
                {
                    throw new JSchException("failed to send channel request");
                }
            }
        }
    }
}
