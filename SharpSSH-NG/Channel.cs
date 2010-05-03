using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;
using System.Runtime.CompilerServices;

namespace SharpSSH.NG
{
    public class Channel
    {
        internal const int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
        internal const int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
        internal const int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;

        internal const int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
        internal const int SSH_OPEN_CONNECT_FAILED = 2;
        internal const int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
        internal const int SSH_OPEN_RESOURCE_SHORTAGE = 4;

        static int index = 0;
        private static List<Channel> pool = new List<Channel>();
        internal static Channel getChannel(string type)
        {
            if (type.Equals("session"))
            {
                return new ChannelSession();
            }
            if (type.Equals("shell"))
            {
                return new ChannelShell();
            }
            if (type.Equals("exec"))
            {
                return new ChannelExec();
            }
            if (type.Equals("x11"))
            {
                return new ChannelX11();
            }
            if (type.Equals("auth-agent@openssh.com"))
            {
                return new ChannelAgentForwarding();
            }
            if (type.Equals("direct-tcpip"))
            {
                return new ChannelDirectTCPIP();
            }
            if (type.Equals("forwarded-tcpip"))
            {
                return new ChannelForwardedTCPIP();
            }
            if (type.Equals("sftp"))
            {
                return new ChannelSftp();
            }
            if (type.Equals("subsystem"))
            {
                return new ChannelSubsystem();
            }
            return null;
        }
        internal static Channel getChannel(int id, Session session)
        {
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    Channel c = pool[i];
                    if (c.id == id && c.session == session) return c;
                }
            }
            return null;
        }
        internal static void del(Channel c)
        {
            lock (pool)
            {
                pool.Remove(c);
            }
        }

        protected int id;
        protected int recipient = -1;
        protected byte[] type = "foo".getBytes();
        internal int lwsize_max = 0x100000;
        //int lwsize_max=0x20000;  // 32*1024*4
        internal int lwsize = 0x100000; // lwsize_max;  // local initial window size
        protected int lmpsize = 0x4000;     // local maximum packet size
        //int lmpsize=0x8000;     // local maximum packet size

        internal int rwsize = 0;         // remote initial window size
        protected int rmpsize = 0;        // remote maximum packet size

        internal IO io = null;
        protected Thread thread = null;

        internal bool eof_local = false;
        internal bool eof_remote = false;

        internal bool close = false;
        protected bool connected = false;

        internal int exitstatus = -1;

        internal int reply = 0;
        internal int connectTimeout = 0;

        private Session session;

        internal int notifyme = 0;

        internal Channel()
        {
            lock (pool)
            {
                id = index++;
                pool.Add(this);
            }
        }
        internal void setRecipient(int foo)
        {
            this.recipient = foo;
        }
        internal int getRecipient()
        {
            return recipient;
        }

        internal virtual void init()
        {
        }

        public virtual void connect()
        {
            connect(0);
        }

        public void connect(int connectTimeout)
        {
            Session _session = getSession();
            if (!_session.Connected)
            {
                throw new JSchException("session is down");
            }
            this.connectTimeout = connectTimeout;
            try
            {
                Buffer buf = new Buffer(100);
                Packet packet = new Packet(buf);
                // send
                // byte   SSH_MSG_CHANNEL_OPEN(90)
                // string channel type         //
                // uint32 sender channel       // 0
                // uint32 initial window size  // 0x100000(65536)
                // uint32 maxmum packet size   // 0x4000(16384)
                packet.reset();
                buf.putByte((byte)90);
                buf.putString(this.type);
                buf.putInt(this.id);
                buf.putInt(this.lwsize);
                buf.putInt(this.lmpsize);
                _session.write(packet);
                int retry = 1000;
                long start = JavaCompat.CurrentTimeMillis();
                long timeout = connectTimeout;
                while (this.getRecipient() == -1 &&
                  _session.Connected &&
                  retry > 0)
                {
                    if (timeout > 0L)
                    {
                        if ((JavaCompat.CurrentTimeMillis() - start) > timeout)
                        {
                            retry = 0;
                            continue;
                        }
                    }
                    try { Thread.Sleep(50); }
                    catch  { }
                    retry--;
                }
                if (!_session.Connected)
                {
                    throw new JSchException("session is down");
                }
                if (retry == 0)
                {
                    throw new JSchException("channel is not opened.");
                }

                /*
                 * At the failure in opening the channel on the sshd, 
                 * 'SSH_MSG_CHANNEL_OPEN_FAILURE' will be sent from sshd and it will
                 * be processed in Session#run().
                 */
                if (this.isClosed())
                {
                    throw new JSchException("channel is not opened.");
                }
                connected = true;
                Start();
            }
            catch (Exception e)
            {
                connected = false;
                if (e is JSchException)
                    throw (JSchException)e;
                throw new JSchException(e.ToString(), e);
            }
        }

        public virtual void setXForwarding(bool foo)
        {
        }

        public virtual void Start() { }

        public bool isEOF() { return eof_remote; }

        internal virtual void getData(Buffer buf)
        {
            setRecipient(buf.getInt());
            setRemoteWindowSize(buf.getInt());
            setRemotePacketSize(buf.getInt());
        }

        public virtual void setInputStream(Stream In)
        {
            io.setInputStream(In, false);
        }
        public void setInputStream(Stream In, bool dontclose)
        {
            io.setInputStream(In, dontclose);
        }
        public virtual void setOutputStream(Stream Out)
        {
            io.setOutputStream(Out, false);
        }
        public void setOutputStream(Stream Out, bool dontclose)
        {
            io.setOutputStream(Out, dontclose);
        }
        public void setExtOutputStream(Stream Out)
        {
            io.setExtOutputStream(Out, false);
        }
        public void setExtOutputStream(Stream Out, bool dontclose)
        {
            io.setExtOutputStream(Out, dontclose);
        }
        public Stream getInputStream()
        {
            PipedMemoryStream In = new PipedMemoryStream(
                                     32 * 1024  // this value should be customizable.
                                     );
            io.setOutputStream(In, false);
            return In;
        }
        public Stream getExtInputStream()
        {
            PipedMemoryStream In = new PipedMemoryStream(
                                     32 * 1024  // this value should be customizable.
                                     );
            io.setExtOutputStream(In, false);
            return In;
        }
        public Stream getOutputStream()
        {
            /*
            PipedOutputStream Out=new PipedOutputStream();
            io.setInputStream(new PassiveInputStream(Out
                                                     , 32*1024
                                                     ), false);
            return Out;
            */

            Stream Out = new PrivateOutputStream(this);
            return Out;
        }
        class PrivateOutputStream : Stream
        {
            private Channel channel;


            private int dataLen = 0;
            private Buffer buffer = null;
            private Packet packet = null;
            private bool closed = false;

            internal PrivateOutputStream(Channel channel)
            {
                this.channel = channel;
            }

            [MethodImpl(MethodImplOptions.Synchronized)]
            private void Init()
            {
                buffer = new Buffer(channel.rmpsize);
                packet = new Packet(buffer);

                byte[] _buf = buffer.buffer;
                if (_buf.Length - (14 + 0) - 32 - 20 <= 0)
                {
                    buffer = null;
                    packet = null;
                    throw new IOException("failed to initialize the channel.");
                }

            }
            byte[] b = new byte[1];
            public void Write(int w)
            {
                b[0] = (byte)w;
                Write(b, 0, 1);
            }
            public override void Write(byte[] buf, int s, int l)
            {
                if (packet == null)
                {
                    Init();
                }

                if (closed)
                {
                    throw new IOException("Already closed");
                }

                byte[] _buf = buffer.buffer;
                int _bufl = _buf.Length;
                while (l > 0)
                {
                    int _l = l;
                    if (l > _bufl - (14 + dataLen) - 32 - 20)
                    {
                        _l = _bufl - (14 + dataLen) - 32 - 20;
                    }

                    if (_l <= 0)
                    {
                        Flush();
                        continue;
                    }

                    Array.Copy(buf, s, _buf, 14 + dataLen, _l);
                    dataLen += _l;
                    s += _l;
                    l -= _l;
                }
            }

            public override void Flush()
            {
                if (closed)
                {
                    throw new IOException("Already closed");
                }
                if (dataLen == 0)
                    return;
                packet.reset();
                buffer.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                buffer.putInt(channel.recipient);
                buffer.putInt(dataLen);
                buffer.skip(dataLen);
                try
                {
                    int foo = dataLen;
                    dataLen = 0;
                    channel.getSession().write(packet, channel, foo);
                }
                catch (Exception e)
                {
                    Close();
                    throw new IOException(e.Message,e);
                }

            }
            public override void Close()
            {
                if (packet == null)
                {
                    try
                    {
                        channel.init();
                    }
                    catch (IOException )
                    {
                        // close should be finished silently.
                        return;
                    }
                }
                if (closed)
                {
                    return;
                }
                if (dataLen > 0)
                {
                    Flush();
                }
                channel.eof();
                closed = true;
            }

            public override bool CanRead
            {
                get { return false; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return true; }
            }


            public override long Length
            {
                get { throw new NotImplementedException(); }
            }

            public override long Position
            {
                get
                {
                    throw new NotImplementedException();
                }
                set
                {
                    throw new NotImplementedException();
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

        }
        internal void setLocalWindowSizeMax(int foo) { this.lwsize_max = foo; }
        internal void setLocalWindowSize(int foo) { this.lwsize = foo; }
        internal void setLocalPacketSize(int foo) { this.lmpsize = foo; }
        [MethodImpl(MethodImplOptions.Synchronized)]
        internal void setRemoteWindowSize(int foo) { this.rwsize = foo; }
        [MethodImpl(MethodImplOptions.Synchronized)]
        internal void addRemoteWindowSize(int foo)
        {
            this.rwsize += foo;
            if (notifyme > 0)
               Monitor.PulseAll(this.thread);
        }
        internal void setRemotePacketSize(int foo) { this.rmpsize = foo; }

        public virtual void run()
        {
        }

        internal virtual void write(byte[] foo)
        {
            write(foo, 0, foo.Length);
        }
        internal virtual void write(byte[] foo, int s, int l)
        {
            try
            {
                io.put(foo, s, l);
            }
            catch (NullReferenceException ) { }
        }
        internal virtual void write_ext(byte[] foo, int s, int l)
        {
            try
            {
                io.put_ext(foo, s, l);
            }
            catch (NullReferenceException ) { }
        }

        internal void EofRemote()
        {
            eof_remote = true;
            try
            {
                io.out_close();
            }
            catch (NullReferenceException ) { }
        }

        protected void eof()
        {
            //Console.Error.WriteLine("EOF!!!! "+this);
            if (close) return;
            if (eof_local) return;
            eof_local = true;
            //close=eof;
            try
            {
                Buffer buf = new Buffer(100);
                Packet packet = new Packet(buf);
                packet.reset();
                buf.putByte((byte)Session.SSH_MSG_CHANNEL_EOF);
                buf.putInt(getRecipient());
                getSession().write(packet);
            }
            catch //(Exception e)
            {
                //Console.Error.WriteLine("Channel.eof");
                //e.printStackTrace();
            }
            /*
            if(!isConnected()){ disconnect(); }
            */
        }

        /*
        http://www1.ietf.org/internet-drafts/draft-ietf-secsh-connect-24.txt

      5.3  Closing a Channel
        When a party will no longer send more data to a channel, it SHOULD
         send SSH_MSG_CHANNEL_EOF.

                  byte      SSH_MSG_CHANNEL_EOF
                  uint32    recipient_channel

        No explicit response is sent to this message.  However, the
         application may send EOF to whatever is at the other end of the
        channel.  Note that the channel remains open after this message, and
         more data may still be sent in the other direction.  This message
         does not consume window space and can be sent even if no window space
         is available.

           When either party wishes to terminate the channel, it sends
           SSH_MSG_CHANNEL_CLOSE.  Upon receiving this message, a party MUST
         send back a SSH_MSG_CHANNEL_CLOSE unless it has already sent this
         message for the channel.  The channel is considered closed for a
           party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and
         the party may then reuse the channel number.  A party MAY send
         SSH_MSG_CHANNEL_CLOSE without having sent or received
         SSH_MSG_CHANNEL_EOF.

                  byte      SSH_MSG_CHANNEL_CLOSE
                  uint32    recipient_channel

         This message does not consume window space and can be sent even if no
         window space is available.

         It is recommended that any data sent before this message is delivered
           to the actual destination, if possible.
        */

        protected void Close()
        {
            //Console.Error.WriteLine("close!!!!");
            if (close) return;
            close = true;

            eof_local = eof_remote = true;

            try
            {
                Buffer buf = new Buffer(100);
                Packet packet = new Packet(buf);
                packet.reset();
                buf.putByte((byte)Session.SSH_MSG_CHANNEL_CLOSE);
                buf.putInt(getRecipient());
                getSession().write(packet);
            }
            catch //(Exception e)
            {
                //e.printStackTrace();
            }
        }
        public bool isClosed()
        {
            return close;
        }
        internal static void disconnect(Session session)
        {
            Channel[] channels = null;
            int count = 0;
            lock (pool)
            {
                channels = new Channel[pool.Count];
                for (int i = 0; i < pool.Count; i++)
                {
                    try
                    {
                        Channel c = pool[i];
                        if (c.session == session)
                        {
                            channels[count++] = c;
                        }
                    }
                    catch // (Exception e)
                    {
                    }
                }
            }
            for (int i = 0; i < count; i++)
            {
                channels[i].disconnect();
            }
        }

        public virtual void disconnect()
        {
            //Console.Error.WriteLine(this+":disconnect "+io+" "+connected);
            //Thread.dumpStack();

            lock (this)
            {
                if (!connected)
                {
                    return;
                }
                connected = false;
            }

            try
            {
                Close();

                eof_remote = eof_local = true;

                thread = null;

                try
                {
                    if (io != null)
                    {
                        io.Close();
                    }
                }
                catch //(Exception e)
                {
                    //e.printStackTrace();
                }
                // io=null;
            }
            finally
            {
                Channel.del(this);
            }
        }

        public bool isConnected()
        {
            Session _session = this.session;
            if (_session != null)
            {
                return _session.Connected && connected;
            }
            return false;
        }
        public bool Connected
        {
            get
            {
                return isConnected();
            }
        }

        public void sendSignal(string signal)
        {
            RequestSignal request = new RequestSignal();
            request.setSignal(signal);
            request.request(getSession(), this);
        }

        //  public string ToString(){
        //      return "Channel: type="+Encoding.UTF8.GetString(type)+",id="+id+",recipient="+recipient+",window_size="+window_size+",packet_size="+packet_size;
        //  }

        /*
          class OutputThread extends Thread{
            Channel c;
            OutputThread(Channel c){ this.c=c;}
            public void run(){c.output_thread();}
          }
        */

        

        internal void setExitStatus(int status) { exitstatus = status; }
        public int getExitStatus() { return exitstatus; }

        internal void setSession(Session session)
        {
            this.session = session;
        }

        public Session getSession()
        {
            Session _session = session;
            if (_session == null)
            {
                throw new JSchException("session is not available");
            }
            return _session;
        }
        public int getId() { return id; }

        protected void sendOpenConfirmation()
        {
            Buffer buf = new Buffer(100);
            Packet packet = new Packet(buf);
            packet.reset();
            buf.putByte((byte)SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
            buf.putInt(getRecipient());
            buf.putInt(id);
            buf.putInt(lwsize);
            buf.putInt(lmpsize);
            getSession().write(packet);
        }

        protected void sendOpenFailure(int reasoncode)
        {
            try
            {
                Buffer buf = new Buffer(100);
                Packet packet = new Packet(buf);
                packet.reset();
                buf.putByte((byte)SSH_MSG_CHANNEL_OPEN_FAILURE);
                buf.putInt(getRecipient());
                buf.putInt(reasoncode);
                buf.putString("open failed".getBytes());
                buf.putString("".getBytes());
                getSession().write(packet);
            }
            catch //(Exception e)
            {
            }
        }
    }
}
