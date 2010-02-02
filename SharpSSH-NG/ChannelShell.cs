using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class ChannelShell : ChannelSession
    {
        ChannelShell()
            : base()
        {
            pty = true;
        }

        public void start()
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
                if (e is Throwable)
                    throw new JSchException("ChannelShell", (Throwable)e);
                throw new JSchException("ChannelShell");
            }

            if (io.In != null)
            {
                thread = new Thread(this);
                thread.setName("Shell for " + _session.host);
                if (_session.daemon_thread)
                {
                    thread.setDaemon(_session.daemon_thread);
                }
                thread.start();
            }
        }

        void init()
        {
            io.setInputStream(getSession().In);
            io.setOutputStream(getSession().Out);
        }
    }
}
