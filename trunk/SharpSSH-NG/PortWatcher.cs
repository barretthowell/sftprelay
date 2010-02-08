using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.IO;

namespace SharpSSH.NG
{
    class PortWatcher
    {
        private static List<PortWatcher> pool = new List<PortWatcher>();
        private static IPAddress anyLocalAddress = IPAddress.Any;

        internal Session session;
        internal int lport;
        internal int rport;
        internal string host;
        internal IPAddress boundaddress;
        internal Thread thread;
        internal TcpListener ss;

        internal static string[] getPortForwarding(Session session)
        {
            List<string> foo = new List<string>();
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    if (pool[i].session == session)
                    {
                        foo.Add(pool[i].lport + ":" + pool[i].host + ":" + pool[i].rport);
                    }
                }
            }
            return foo.ToArray();
        }
        internal static PortWatcher getPort(Session session, string address, int lport)
        {
            IPAddress addr;
            try
            {
                addr = Dns.GetHostEntry(address).AddressList[0]; // IPAddress.Parse(address); // InetAddress.getByName(address);
            }
            catch (Exception uhe)
            {
                throw new JSchException("PortForwardingL: invalid address " + address + " specified.", uhe);
            }
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    if (pool[i].session == session && pool[i].lport == lport)
                    {
                        if (/*p.boundaddress.isAnyLocalAddress() ||*/
                               (anyLocalAddress != null && pool[i].boundaddress.Equals(anyLocalAddress)) ||
                           pool[i].boundaddress.Equals(addr))
                            return pool[i];
                    }
                }
                return null;
            }
        }
        internal static PortWatcher addPort(Session session, string address, int lport, string host, int rport, ServerSocketFactory ssf)
        {
            if (getPort(session, address, lport) != null)
            {
                throw new JSchException("PortForwardingL: local port " + address + ":" + lport + " is already registered.");
            }
            PortWatcher pw = new PortWatcher(session, address, lport, host, rport, ssf);
            pool.Add(pw);
            return pw;
        }
        internal static void delPort(Session session, string address, int lport)
        {
            PortWatcher pw = getPort(session, address, lport);
            if (pw == null)
            {
                throw new JSchException("PortForwardingL: local port " + address + ":" + lport + " is not registered.");
            }
            pw.delete();
            pool.Remove(pw);
        }
        internal static void delPort(Session session)
        {
            lock (pool)
            {
                PortWatcher[] foo = new PortWatcher[pool.Count];
                int count = 0;
                for (int i = 0; i < pool.Count; i++)
                {
                    PortWatcher p = pool[i];
                    if (p.session == session)
                    {
                        p.delete();
                        foo[count++] = p;
                    }
                }
                for (int i = 0; i < count; i++)
                {
                    PortWatcher p = foo[i];
                    pool.Remove(p);
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
                boundaddress = Dns.GetHostEntry(address).AddressList[0];
                ss = (factory == null) ?
                  new TcpListener(boundaddress,lport) :
                  factory.createServerSocket(lport, 0, boundaddress);
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
                string message = "PortForwardingL: local port " + address + ":" + lport + " cannot be bound.";
                throw new JSchException(message,e);
            }
            if (lport == 0)
            {
                int assigned = ((IPEndPoint)ss.LocalEndpoint).Port;
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
                    Stream In = socket.GetStream();
                    Stream Out = socket.GetStream();
                    ChannelDirectTCPIP channel = new ChannelDirectTCPIP();
                    channel.init();
                    channel.setInputStream(In);
                    channel.setOutputStream(Out);
                    session.addChannel(channel);
                    ((ChannelDirectTCPIP)channel).setHost(host);
                    ((ChannelDirectTCPIP)channel).setPort(rport);
                    ((ChannelDirectTCPIP)channel).setOrgIPAddress(socket.Client.RemoteHost());
                    ((ChannelDirectTCPIP)channel).setOrgPort(socket.Client.RemotePort());
                    channel.connect();
                    if (channel.exitstatus != -1)
                    {
                    }
                }
            }
            catch //(Exception e)
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
                if (ss != null) ss.Stop();
                ss = null;
            }
            catch //(Exception e)
            {
            }
        }
    }
}
