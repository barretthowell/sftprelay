using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class ChannelExec : ChannelSession
    {
        byte[] command = new byte[0];

        public void start()
        {
            Session _session = getSession();
            try
            {
                sendRequests();
                Request request = new RequestExec(command);
                request.request(_session, this);
            }
            catch (Exception e)
            {
                if (e is JSchException) throw (JSchException)e;
                if (e is Throwable)
                    throw new JSchException("ChannelExec", (Throwable)e);
                throw new JSchException("ChannelExec");
            }

            if (io.In != null)
            {
                thread = new Thread(this);
                thread.setName("Exec thread " + _session.getHost());
                if (_session.daemon_thread)
                {
                    thread.setDaemon(_session.daemon_thread);
                }
                thread.start();
            }
        }

        public void setCommand(string command)
        {
            this.command = command.getBytes();
        }
        public void setCommand(byte[] command)
        {
            this.command = command;
        }

        void init()
        {
            io.setInputStream(getSession().In);
            io.setOutputStream(getSession().Out);
        }

        public void setErrStream(java.io.OutputStream Out)
        {
            setExtOutputStream(Out);
        }
        public void setErrStream(java.io.OutputStream Out, bool dontclose)
        {
            setExtOutputStream(Out, dontclose);
        }
        public java.io.InputStream getErrStream()
        {
            return getExtInputStream();
        }
    }
}
