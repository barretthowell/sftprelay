using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading;
using System.Net.Sockets;

namespace SharpSSH.NG
{
    //FIXME: Dirty dirty code
    class ChannelForwardedTCPIP : Channel
    {
        static List<object> pool = new List<object>();

        private const int LOCAL_WINDOW_SIZE_MAX = 0x20000;
        //private const int LOCAL_WINDOW_SIZE_MAX=0x100000;
        private const int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

        private const int TIMEOUT = 10 * 1000;

        SocketFactory factory = null;
        private TcpClient socket = null;
        private ForwardedTCPIPDaemon daemon = null;
        string target;
        int lport;
        int rport;

        internal ChannelForwardedTCPIP() :
            base()
        {
            setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
            setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
            setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
            io = new IO();
            connected = true;
        }

        public override void run()
        {
            try
            {
                if (lport == -1)
                {
                    Type c = Type.GetType(target);
                    daemon = (ForwardedTCPIPDaemon)c.newInstance();

                    MemoryStream Out = new MemoryStream(32 * 1024);
                    /*
                    PipedOutputStream Out = new PipedOutputStream();
                    io.setInputStream(new PassiveInputStream(Out
                                                             , 32 * 1024
                                                             ), false);
                    */
                    io.setInputStream(Out);
                    daemon.setChannel(this, getInputStream(), Out);
                    object[] foo = getPort(getSession(), rport);
                    daemon.setArg((object[])foo[3]);

                    new Thread(new ThreadStart(daemon.run)).Start();
                }
                else
                {
                    socket = (factory == null) ?
                       Util.createSocket(target, lport, TIMEOUT) :
                      factory.createSocket(target, lport);
                    socket.NoDelay=true;
                    io.setInputStream(socket.GetStream());
                    io.setOutputStream(socket.GetStream());
                }
                sendOpenConfirmation();
            }
            catch //(Exception e)
            {
                sendOpenFailure(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
                close = true;
                disconnect();
                return;
            }

            thread = Thread.CurrentThread;
            Buffer buf = new Buffer(rmpsize);
            Packet packet = new Packet(buf);
            int i = 0;
            try
            {
                while (thread != null &&
                      io != null &&
                      io.In != null)
                {
                    i = io.In.Read(buf.buffer,
                                 14,
                                 buf.buffer.Length - 14
                                 - 32 - 20 // padding and mac
                                 );
                    if (i <= 0)
                    {
                        eof();
                        break;
                    }
                    packet.reset();
                    if (close) break;
                    buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                    buf.putInt(recipient);
                    buf.putInt(i);
                    buf.skip(i);
                    getSession().write(packet, this, i);
                }
            }
            catch //(Exception e)
            {
                //Console.Error.WriteLine(e);
            }
            //thread=null;
            //eof();
            disconnect();
        }

        internal override void getData(Buffer buf)
        {
            setRecipient(buf.getInt());
            setRemoteWindowSize(buf.getInt());
            setRemotePacketSize(buf.getInt());
            byte[] addr = buf.getString();
            int port = buf.getInt();
            byte[] orgaddr = buf.getString();
            int orgport = buf.getInt();

            /*
            Console.Error.WriteLine("addr: "+Encoding.UTF8.GetString(addr));
            Console.Error.WriteLine("port: "+port);
            Console.Error.WriteLine("orgaddr: "+Encoding.UTF8.GetString(orgaddr));
            Console.Error.WriteLine("orgport: "+orgport);
            */

            Session _session = null;
            try
            {
                _session = getSession();
            }
            catch (JSchException)
            {
                // session has been already down.
            }

            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    object[] foo = (object[])(pool[i]);
                    if (foo[0] != _session) continue;
                    if (((int)foo[1]) != port) continue;
                    this.rport = port;
                    this.target = (string)foo[2];
                    if (foo[3] == null || (foo[3] is object[])) { this.lport = -1; }
                    else { this.lport = ((int)foo[3]); }
                    if (foo.Length >= 6)
                    {
                        this.factory = ((SocketFactory)foo[5]);
                    }
                    break;
                }
                if (target == null)
                {
                    //Console.Error.WriteLine("??");
                }
            }
        }

        static object[] getPort(Session session, int rport)
        {
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    object[] bar = (object[])(pool[i]);
                    if (bar[0] != session) continue;
                    if (((int)bar[1]) != rport) continue;
                    return bar;
                }
                return null;
            }
        }

        static string[] getPortForwarding(Session session)
        {
            List<string> foo = new List<string>();
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    object[] bar = (object[])(pool[i]);
                    if (bar[0] != session) continue;
                    if (bar[3] == null) { foo.Add(bar[1] + ":" + bar[2] + ":"); }
                    else { foo.Add(bar[1] + ":" + bar[2] + ":" + bar[3]); }
                }
            }
            return foo.ToArray();
        }

        internal static string normalize(string address)
        {
            if (address == null) { return "localhost"; }
            else if (address.Length == 0 || address.Equals("*")) { return ""; }
            else { return address; }
        }

        internal static void addPort(Session session, string _address_to_bind, int port, string target, int lport, SocketFactory factory)
        {
            string address_to_bind = normalize(_address_to_bind);
            lock (pool)
            {
                if (getPort(session, port) != null)
                {
                    throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
                }
                object[] foo = new object[6];
                foo[0] = session; foo[1] = port;
                foo[2] = target; foo[3] = lport;
                foo[4] = address_to_bind;
                foo[5] = factory;
                pool.Add(foo);
            }
        }
        internal static void addPort(Session session, string _address_to_bind, int port, string daemon, Object[] arg)
        {
            string address_to_bind = normalize(_address_to_bind);
            lock (pool)
            {
                if (getPort(session, port) != null)
                {
                    throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
                }
                object[] foo = new object[5];
                foo[0] = session; foo[1] = port;
                foo[2] = daemon; foo[3] = arg;
                foo[4] = address_to_bind;
                pool.Add(foo);
            }
        }
        internal static void delPort(ChannelForwardedTCPIP c)
        {
            Session _session = null;
            try
            {
                _session = c.getSession();
            }
            catch (JSchException )
            {
                // session has been already down.
            }
            if (_session != null)
                delPort(_session, c.rport);
        }
        internal static void delPort(Session session, int rport)
        {
            delPort(session, null, rport);
        }
        internal static void delPort(Session session, string address_to_bind, int rport)
        {
            lock (pool)
            {
                object[] foo = null;
                for (int i = 0; i < pool.Count; i++)
                {
                    object[] bar = (object[])(pool[i]);
                    if (bar[0] != session) continue;
                    if (((int)bar[1]) != rport) continue;
                    foo = bar;
                    break;
                }
                if (foo == null) return;
                pool.Remove(foo);
                if (address_to_bind == null)
                {
                    address_to_bind = (string)foo[4];
                }
                if (address_to_bind == null)
                {
                    address_to_bind = "0.0.0.0";
                }
            }

            Buffer buf = new Buffer(100); // ??
            Packet packet = new Packet(buf);

            try
            {
                // byte SSH_MSG_GLOBAL_REQUEST 80
                // string "cancel-tcpip-forward"
                // bool want_reply
                // string  address_to_bind (e.g. "127.0.0.1")
                // uint32  port number to bind
                packet.reset();
                buf.putByte((byte)80/*SSH_MSG_GLOBAL_REQUEST*/);
                buf.putString("cancel-tcpip-forward".getBytes());
                buf.putByte((byte)0);
                buf.putString(address_to_bind.getBytes());
                buf.putInt(rport);
                session.write(packet);
            }
            catch //(Exception e)
            {
                //    throw new JSchException(e.ToString());
            }
        }
        internal static void delPort(Session session)
        {
            int[] rport = null;
            int count = 0;
            lock (pool)
            {
                rport = new int[pool.Count];
                for (int i = 0; i < pool.Count; i++)
                {
                    object[] bar = (object[])(pool[i]);
                    if (bar[0] == session)
                    {
                        rport[count++] = ((int)bar[1]);
                    }
                }
            }
            for (int i = 0; i < count; i++)
            {
                delPort(session, rport[i]);
            }
        }

        public int getRemotePort() { return rport; }
        void setSocketFactory(SocketFactory factory)
        {
            this.factory = factory;
        }
    }
}
