using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;

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
        public override void Start()
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
                throw new JSchException("ChannelSubsystem",e);
            }
            if (io.In != null)
            {
                thread = new Thread(this.run);
                thread.Name="Subsystem for " + _session.host;
                if (_session.daemon_thread)
                {
                    thread.IsBackground=_session.daemon_thread;
                }
                thread.Start();
            }
        }

        internal override void init()
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
