using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SharpSSH.NG
{
    class ChannelSubsystem : ChannelSession
    {
        //bool pty = false;
        bool want_reply = true;
        string subsystem = "";
        public override void setXForwarding(bool foo) { xforwading = true; }
        public override void setPty(bool foo) { pty = foo; }
        public void setWantReply(bool foo) { want_reply = foo; }
        public void setSubsystem(string foo) { subsystem = foo; }
        public override void start()
        {
            Session _session = getSession();
            try
            {
                Request request;
                if (xforwading)
                {
                    request = new RequestX11();
                    request.request(_session, this);
                }
                if (pty)
                {
                    request = new RequestPtyReq();
                    request.request(_session, this);
                }
                request = new RequestSubsystem();
                ((RequestSubsystem)request).request(_session, this, subsystem, want_reply);
            }
            catch (Exception e)
            {
                if (e is JSchException) { throw (JSchException)e; }
                if (e is Throwable)
                    throw new JSchException("ChannelSubsystem", (Throwable)e);
                throw new JSchException("ChannelSubsystem");
            }
            if (io.In != null)
            {
                thread = new Thread(this.run);
                thread.setName("Subsystem for " + _session.host);
                if (_session.daemon_thread)
                {
                    thread.setDaemon(_session.daemon_thread);
                }
                thread.start();
            }
        }

        protected override void init()
        {
            io.setInputStream(getSession().In);
            io.setOutputStream(getSession().Out);
        }

        public void setErrStream(Stream Out)
        {
            setExtOutputStream(Out);
        }
        public Stream getErrStream()
        {
            return getExtInputStream();
        }
    }
}
