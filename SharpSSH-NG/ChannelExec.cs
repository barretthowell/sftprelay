using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;

namespace SharpSSH.NG
{
    class ChannelExec : ChannelSession
    {
        byte[] command = new byte[0];

        public override void Start()
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
                throw new JSchException("ChannelExec",e);
            }

            if (io.In != null)
            {
                thread = new Thread(this.run);
                thread.Name="Exec thread " + _session.getHost();
                if (_session.daemon_thread)
                {
                    thread.IsBackground=_session.daemon_thread;
                }
                thread.Start();
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

        internal override void init()
        {
            io.setInputStream(getSession().In);
            io.setOutputStream(getSession().Out);
        }

        public void setErrStream(Stream Out)
        {
            setExtOutputStream(Out);
        }
        public void setErrStream(Stream Out, bool dontclose)
        {
            setExtOutputStream(Out, dontclose);
        }
        public Stream getErrStream()
        {
            return getExtInputStream();
        }
    }
}
