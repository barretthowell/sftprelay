using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace SharpSSH.NG
{
    class ChannelShell : ChannelSession
    {
        internal ChannelShell()
            : base()
        {
            pty = true;
        }

        public override void Start()
        {
            Session _session = getSession();
            try
            {
                sendRequests();

                Request request = new RequestShell();
                request.request(_session, this);
            }
            catch (Exception e)
            {
                if (e is JSchException) throw (JSchException)e;
                throw new JSchException("ChannelShell",e);
            }

            if (io.In != null)
            {
                thread = new Thread(this.run);
                thread.Name="Shell for " + _session.host;
                if (_session.daemon_thread)
                {
                    thread.IsBackground = _session.daemon_thread;
                }
                thread.Start();
            }
        }

        internal override void init()
        {
            io.setInputStream(getSession().In);
            io.setOutputStream(getSession().Out);
        }
    }
}
