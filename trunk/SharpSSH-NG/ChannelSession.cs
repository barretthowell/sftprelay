using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class ChannelSession : Channel
    {
        private static byte[] _session = "session".getBytes();

        protected bool agent_forwarding = false;
        protected bool xforwading = false;
        protected Hashtable env = null;

        protected bool pty = false;

        protected string ttype = "vt100";
        protected int tcol = 80;
        protected int trow = 24;
        protected int twp = 640;
        protected int thp = 480;
        protected byte[] terminal_mode = null;

        ChannelSession()
            : base()
        {
            type = _session;
            io = new IO();
        }

        /**
         * Enable the agent forwarding.
         *
         * @param enable
         */
        public void setAgentForwarding(bool enable)
        {
            agent_forwarding = enable;
        }

        /**
         * Enable the X11 forwarding.
         *
         * @param enable
         * @see RFC4254 6.3.1. Requesting X11 Forwarding
         */
        public void setXForwarding(bool enable)
        {
            xforwading = enable;
        }

        /**
         * @deprecated Use {@link #setEnv(string, string)} or {@link #setEnv(byte[], byte[])} instead.
         * @see #setEnv(string, string)
         * @see #setEnv(byte[], byte[])
         */
        public void setEnv(Hashtable env)
        {
            lock (this)
            {
                this.env = env;
            }
        }

        /**
         * Set the environment variable. 
         * If <code>name</code> and <code>value</code> are needed to be passed 
         * to the remote in your faivorite encoding,use 
         * {@link #setEnv(byte[], byte[])}.
         *
         * @param name A name for environment variable.
         * @param value A value for environment variable.
         * @see RFC4254 6.4 Environment Variable Passing
         */
        public void setEnv(string name, string value)
        {
            setEnv(name.getBytes(), value.getBytes());
        }

        /**
         * Set the environment variable.
         *
         * @param name A name of environment variable.
         * @param value A value of environment variable.
         * @see #setEnv(string, string)
         * @see RFC4254 6.4 Environment Variable Passing
         */
        public void setEnv(byte[] name, byte[] value)
        {
            lock (this)
            {
                getEnv().put(name, value);
            }
        }

        private Hashtable getEnv()
        {
            if (env == null)
                env = new Hashtable();
            return env;
        }

        /**
         * Allocate a Pseudo-Terminal.
         *
         * @param enable
         * @see RFC4254 6.2. Requesting a Pseudo-Terminal
         */
        public void setPty(bool enable)
        {
            pty = enable;
        }

        /**
         * Set the terminal mode.
         * 
         * @param terminal_mode
         */
        public void setTerminalMode(byte[] terminal_mode)
        {
            this.terminal_mode = terminal_mode;
        }

        /**
         * Change the window dimension interactively.
         * 
         * @param col terminal width, columns
         * @param row terminal height, rows
         * @param wp terminal width, pixels
         * @param hp terminal height, pixels
         * @see RFC4254 6.7. Window Dimension Change Message
         */
        public void setPtySize(int col, int row, int wp, int hp)
        {
            setPtyType(this.ttype, col, row, wp, hp);
            if (!pty || !isConnected())
            {
                return;
            }
            try
            {
                RequestWindowChange request = new RequestWindowChange();
                request.setSize(col, row, wp, hp);
                request.request(getSession(), this);
            }
            catch (Exception e)
            {
                //System.err.println("ChannelSessio.setPtySize: "+e);
            }
        }

        /**
         * Set the terminal type.
         * This method is not effective after Channel#connect().
         *
         * @param ttype terminal type(for example, "vt100")
         * @see #setPtyType(string, int, int, int, int)
         */
        public void setPtyType(string ttype)
        {
            setPtyType(ttype, 80, 24, 640, 480);
        }

        /**
         * Set the terminal type.
         * This method is not effective after Channel#connect().
         *
         * @param ttype terminal type(for example, "vt100")
         * @param col terminal width, columns
         * @param row terminal height, rows
         * @param wp terminal width, pixels
         * @param hp terminal height, pixels
         */
        public void setPtyType(string ttype, int col, int row, int wp, int hp)
        {
            this.ttype = ttype;
            this.tcol = col;
            this.trow = row;
            this.twp = wp;
            this.thp = hp;
        }

        protected void sendRequests()
        {
            Session _session = getSession();
            Request request;
            if (agent_forwarding)
            {
                request = new RequestAgentForwarding();
                request.request(_session, this);
            }

            if (xforwading)
            {
                request = new RequestX11();
                request.request(_session, this);
            }

            if (pty)
            {
                request = new RequestPtyReq();
                ((RequestPtyReq)request).setTType(ttype);
                ((RequestPtyReq)request).setTSize(tcol, trow, twp, thp);
                if (terminal_mode != null)
                {
                    ((RequestPtyReq)request).setTerminalMode(terminal_mode);
                }
                request.request(_session, this);
            }

            if (env != null)
            {
                for (Enumeration _env = env.keys(); _env.hasMoreElements(); )
                {
                    Object name = _env.nextElement();
                    Object value = env.get(name);
                    request = new RequestEnv();
                    ((RequestEnv)request).setEnv(toByteArray(name),
                                                 toByteArray(value));
                    request.request(_session, this);
                }
            }
        }

        private byte[] toByteArray(Object o)
        {
            if (o is string)
            {
                return ((string)o).getBytes();
            }
            return (byte[])o;
        }

        public void run()
        {
            //System.err.println(this+":run >");

            Buffer buf = new Buffer(rmpsize);
            Packet packet = new Packet(buf);
            int i = -1;
            try
            {
                while (isConnected() &&
                  thread != null &&
                      io != null &&
                      io.In != null)
                {
                    i = io.In.read(buf.buffer,
                                 14,
                                 buf.buffer.length - 14
                                 - 32 - 20 // padding and mac
                         );
                    if (i == 0) continue;
                    if (i == -1)
                    {
                        eof();
                        break;
                    }
                    if (close) break;
                    //System.Out.println("write: "+i);
                    packet.reset();
                    buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                    buf.putInt(recipient);
                    buf.putInt(i);
                    buf.skip(i);
                    getSession().write(packet, this, i);
                }
            }
            catch (Exception e)
            {
                //System.err.println("# ChannelExec.run");
                //e.printStackTrace();
            }
            if (thread != null)
            {
                lock (thread) { thread.notifyAll(); }
            }
            thread = null;
            //System.err.println(this+":run <");
        }
    }
}
