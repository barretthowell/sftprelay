using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace SharpSSH.NG
{
    class PortWatcher
    {
        private static List<PortWatcher> pool = new List<PortWatcher>();
        private static IPAddress anyLocalAddress = IPAddress.Any;

        Session session;
        int lport;
        int rport;
        string host;
        IPAddress boundaddress;
        Thread thread;
        TcpListener ss;

        static string[] getPortForwarding(Session session)
        {
            List<string> foo = new List<string>();
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    if (pool[i].session == session)
                    {
                        foo.Add(p.lport + ":" + p.host + ":" + p.rport);
                    }
                }
            }
            return foo.ToArray();
        }
        static PortWatcher getPort(Session session, string address, int lport)
        {
            IPAddress addr;
            try
            {
                addr = IPAddress.Parse(address); // InetAddress.getByName(address);
            }
            catch (FormatException uhe)
            {
                throw new JSchException("PortForwardingL: invalid address " + address + " specified.", uhe);
            }
            lock (pool)
            {
                for (int i = 0; i < pool.size(); i++)
                {
                    if (pool[i].session == session && pool[i].lport == lport)
                    {
                        if (/*p.boundaddress.isAnyLocalAddress() ||*/
                               (anyLocalAddress != null && pool[i].boundaddress.equals(anyLocalAddress)) ||
                           pool[i].boundaddress.equals(addr))
                            return pool[i];
                    }
                }
                return null;
            }
        }
        static PortWatcher addPort(Session session, string address, int lport, string host, int rport, ServerSocketFactory ssf)
        {
            if (getPort(session, address, lport) != null)
            {
                throw new JSchException("PortForwardingL: local port " + address + ":" + lport + " is already registered.");
            }
            PortWatcher pw = new PortWatcher(session, address, lport, host, rport, ssf);
            pool.Add(pw);
            return pw;
        }
        static void delPort(Session session, string address, int lport)
        {
            PortWatcher pw = getPort(session, address, lport);
            if (pw == null)
            {
                throw new JSchException("PortForwardingL: local port " + address + ":" + lport + " is not registered.");
            }
            pw.delete();
            pool.Remove(pw);
        }
        static void delPort(Session session)
        {
            lock (pool)
            {
                PortWatcher[] foo = new PortWatcher[pool.size()];
                int count = 0;
                for (int i = 0; i < pool.size(); i++)
                {
                    PortWatcher p = (PortWatcher)(pool.elementAt(i));
                    if (p.session == session)
                    {
                        p.delete();
                        foo[count++] = p;
                    }
                }
                for (int i = 0; i < count; i++)
                {
                    PortWatcher p = foo[i];
                    pool.removeElement(p);
                }
            }
        }
        PortWatcher(Session session,
                string address, int lport,
                string host, int rport,
                    ServerSocketFactory factory)
        {
            this.session = session;
            this.lport = lport;
            this.host = host;
            this.rport = rport;
            try
            {
                boundaddress = InetAddress.getByName(address);
                ss = (factory == null) ?
                  new ServerSocket(lport, 0, boundaddress) :
                  factory.createServerSocket(lport, 0, boundaddress);
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
                string message = "PortForwardingL: local port " + address + ":" + lport + " cannot be bound.";
                if (e is Throwable)
                    throw new JSchException(message, (Throwable)e);
                throw new JSchException(message);
            }
            if (lport == 0)
            {
                int assigned = ss.getLocalPort();
                if (assigned != -1)
                    this.lport = assigned;
            }
        }

        public void run()
        {
            thread = new Thread(this.run);
            try
            {
                while (thread != null)
                {
                    TcpClient socket = ss.AcceptTcpClient();
                    socket.NoDelay=true;
                    Stream In = socket.getStream();
                    Stream Out = socket.getStream();
                    ChannelDirectTCPIP channel = new ChannelDirectTCPIP();
                    channel.init();
                    channel.setInputStream(In);
                    channel.setOutputStream(Out);
                    session.addChannel(channel);
                    ((ChannelDirectTCPIP)channel).setHost(host);
                    ((ChannelDirectTCPIP)channel).setPort(rport);
                    ((ChannelDirectTCPIP)channel).setOrgIPAddress(socket.getInetAddress().getHostAddress());
                    ((ChannelDirectTCPIP)channel).setOrgPort(socket.getPort());
                    channel.connect();
                    if (channel.exitstatus != -1)
                    {
                    }
                }
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine("! "+e);
            }

            delete();
        }

        void delete()
        {
            thread = null;
            try
            {
                if (ss != null) ss.close();
                ss = null;
            }
            catch (Exception e)
            {
            }
        }
    }
}
