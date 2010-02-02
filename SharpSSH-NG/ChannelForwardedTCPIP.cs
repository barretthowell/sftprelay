using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class ChannelForwardedTCPIP : Channel
    {
        static java.util.Vector pool = new java.util.Vector();

        private const int LOCAL_WINDOW_SIZE_MAX = 0x20000;
        //private const int LOCAL_WINDOW_SIZE_MAX=0x100000;
        private const int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

        private const int TIMEOUT = 10 * 1000;

        SocketFactory factory = null;
        private Socket socket = null;
        private ForwardedTCPIPDaemon daemon = null;
        string target;
        int lport;
        int rport;

        ChannelForwardedTCPIP() :
            base()
        {
            setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
            setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
            setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
            io = new IO();
            connected = true;
        }

        public void run()
        {
            try
            {
                if (lport == -1)
                {
                    Class c = Class.forName(target);
                    daemon = (ForwardedTCPIPDaemon)c.newInstance();

                    PipedOutputStream Out = new PipedOutputStream();
                    io.setInputStream(new PassiveInputStream(Out
                                                             , 32 * 1024
                                                             ), false);

                    daemon.setChannel(this, getInputStream(), Out);
                    Object[] foo = getPort(getSession(), rport);
                    daemon.setArg((Object[])foo[3]);

                    new Thread(daemon).start();
                }
                else
                {
                    socket = (factory == null) ?
                       Util.createSocket(target, lport, TIMEOUT) :
                      factory.createSocket(target, lport);
                    socket.setTcpNoDelay(true);
                    io.setInputStream(socket.getInputStream());
                    io.setOutputStream(socket.getOutputStream());
                }
                sendOpenConfirmation();
            }
            catch (Exception e)
            {
                sendOpenFailure(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
                close = true;
                disconnect();
                return;
            }

            thread = Thread.currentThread();
            Buffer buf = new Buffer(rmpsize);
            Packet packet = new Packet(buf);
            int i = 0;
            try
            {
                while (thread != null &&
                      io != null &&
                      io.In != null)
                {
                    i = io.In.read(buf.buffer,
                                 14,
                                 buf.buffer.length - 14
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
            catch (Exception e)
            {
                //System.err.println(e);
            }
            //thread=null;
            //eof();
            disconnect();
        }

        void getData(Buffer buf)
        {
            setRecipient(buf.getInt());
            setRemoteWindowSize(buf.getInt());
            setRemotePacketSize(buf.getInt());
            byte[] addr = buf.getString();
            int port = buf.getInt();
            byte[] orgaddr = buf.getString();
            int orgport = buf.getInt();

            /*
            System.err.println("addr: "+new string(addr));
            System.err.println("port: "+port);
            System.err.println("orgaddr: "+new string(orgaddr));
            System.err.println("orgport: "+orgport);
            */

            Session _session = null;
            try
            {
                _session = getSession();
            }
            catch (JSchException e)
            {
                // session has been already down.
            }

            lock (pool)
            {
                for (int i = 0; i < pool.size(); i++)
                {
                    Object[] foo = (Object[])(pool.elementAt(i));
                    if (foo[0] != _session) continue;
                    if (((Integer)foo[1]).intValue() != port) continue;
                    this.rport = port;
                    this.target = (string)foo[2];
                    if (foo[3] == null || (foo[3] is Object[])) { this.lport = -1; }
                    else { this.lport = ((Integer)foo[3]).intValue(); }
                    if (foo.length >= 6)
                    {
                        this.factory = ((SocketFactory)foo[5]);
                    }
                    break;
                }
                if (target == null)
                {
                    //System.err.println("??");
                }
            }
        }

        static Object[] getPort(Session session, int rport)
        {
            lock (pool)
            {
                for (int i = 0; i < pool.size(); i++)
                {
                    Object[] bar = (Object[])(pool.elementAt(i));
                    if (bar[0] != session) continue;
                    if (((Integer)bar[1]).intValue() != rport) continue;
                    return bar;
                }
                return null;
            }
        }

        static string[] getPortForwarding(Session session)
        {
            java.util.Vector foo = new java.util.Vector();
            lock (pool)
            {
                for (int i = 0; i < pool.size(); i++)
                {
                    Object[] bar = (Object[])(pool.elementAt(i));
                    if (bar[0] != session) continue;
                    if (bar[3] == null) { foo.addElement(bar[1] + ":" + bar[2] + ":"); }
                    else { foo.addElement(bar[1] + ":" + bar[2] + ":" + bar[3]); }
                }
            }
            string[] bar = new string[foo.size()];
            for (int i = 0; i < foo.size(); i++)
            {
                bar[i] = (string)(foo.elementAt(i));
            }
            return bar;
        }

        static string normalize(string address)
        {
            if (address == null) { return "localhost"; }
            else if (address.length() == 0 || address.equals("*")) { return ""; }
            else { return address; }
        }

        static void addPort(Session session, string _address_to_bind, int port, string target, int lport, SocketFactory factory)
        {
            string address_to_bind = normalize(_address_to_bind);
            lock (pool)
            {
                if (getPort(session, port) != null)
                {
                    throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
                }
                Object[] foo = new Object[6];
                foo[0] = session; foo[1] = new Integer(port);
                foo[2] = target; foo[3] = new Integer(lport);
                foo[4] = address_to_bind;
                foo[5] = factory;
                pool.addElement(foo);
            }
        }
        static void addPort(Session session, string _address_to_bind, int port, string daemon, Object[] arg)
        {
            string address_to_bind = normalize(_address_to_bind);
            lock (pool)
            {
                if (getPort(session, port) != null)
                {
                    throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
                }
                Object[] foo = new Object[5];
                foo[0] = session; foo[1] = new Integer(port);
                foo[2] = daemon; foo[3] = arg;
                foo[4] = address_to_bind;
                pool.addElement(foo);
            }
        }
        static void delPort(ChannelForwardedTCPIP c)
        {
            Session _session = null;
            try
            {
                _session = c.getSession();
            }
            catch (JSchException e)
            {
                // session has been already down.
            }
            if (_session != null)
                delPort(_session, c.rport);
        }
        static void delPort(Session session, int rport)
        {
            delPort(session, null, rport);
        }
        static void delPort(Session session, string address_to_bind, int rport)
        {
            lock (pool)
            {
                Object[] foo = null;
                for (int i = 0; i < pool.size(); i++)
                {
                    Object[] bar = (Object[])(pool.elementAt(i));
                    if (bar[0] != session) continue;
                    if (((Integer)bar[1]).intValue() != rport) continue;
                    foo = bar;
                    break;
                }
                if (foo == null) return;
                pool.removeElement(foo);
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
            catch (Exception e)
            {
                //    throw new JSchException(e.toString());
            }
        }
        static void delPort(Session session)
        {
            int[] rport = null;
            int count = 0;
            lock (pool)
            {
                rport = new int[pool.size()];
                for (int i = 0; i < pool.size(); i++)
                {
                    Object[] bar = (Object[])(pool.elementAt(i));
                    if (bar[0] == session)
                    {
                        rport[count++] = ((Integer)bar[1]).intValue();
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
