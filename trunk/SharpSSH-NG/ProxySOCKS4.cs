using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Net;

namespace SharpSSH.NG
{
    class ProxySOCKS4 : Proxy
    {
        private static int DEFAULTPORT = 1080;
        private string proxy_host;
        private int proxy_port;
        private Stream In;
        private Stream Out;
        private TcpClient socket;
        private string user;
        private string passwd;

        public ProxySOCKS4(string proxy_host)
        {
            int port = DEFAULTPORT;
            string host = proxy_host;
            if (proxy_host.IndexOf(':') != -1)
            {
                try
                {
                    host = proxy_host.Substring(0, proxy_host.IndexOf(':'));
                    port = int.Parse(proxy_host.Substring(proxy_host.IndexOf(':') + 1));
                }
                catch //(Exception e)
                {
                }
            }
            this.proxy_host = host;
            this.proxy_port = port;
        }
        public ProxySOCKS4(string proxy_host, int proxy_port)
        {
            this.proxy_host = proxy_host;
            this.proxy_port = proxy_port;
        }
        public void setUserPasswd(string user, string passwd)
        {
            this.user = user;
            this.passwd = passwd;
        }
        public void connect(SocketFactory socket_factory, string host, int port, int timeout)
        {
            try
            {
                if (socket_factory == null)
                {
                    socket = Util.createSocket(proxy_host, proxy_port, timeout);
                    //socket=new Socket(proxy_host, proxy_port);    
                    In = socket.GetStream();
                    Out = socket.GetStream();
                }
                else
                {
                    socket = socket_factory.createSocket(proxy_host, proxy_port);
                    In = socket_factory.GetStream(socket);
                    Out = socket_factory.GetStream(socket);
                }
                if (timeout > 0)
                {
                    socket.setSoTimeout(timeout);
                }
                socket.NoDelay=true;

                byte[] buf = new byte[1024];
                int index = 0;

                /*
                   1) CONNECT
   
                   The client connects to the SOCKS server and sends a CONNECT request when
                   it wants to establish a connection to an application server. The client
                   includes in the request packet the IP address and the port number of the
                   destination host, and userid, in the following format.
   
                               +----+----+----+----+----+----+----+----+----+----+....+----+
                               | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
                               +----+----+----+----+----+----+----+----+----+----+....+----+
                   # of bytes:   1    1      2              4           variable       1
   
                   VN is the SOCKS protocol version number and should be 4. CD is the
                   SOCKS command code and should be 1 for CONNECT request. NULL is a byte
                   of all zero bits.
                */

                index = 0;
                buf[index++] = 4;
                buf[index++] = 1;

                buf[index++] = (byte)(port >> 8);
                buf[index++] = (byte)(port & 0xff);

                try
                {
                    IPAddress addr = Dns.GetHostEntry(host).AddressList[0];
                    byte[] byteAddress = addr.GetAddressBytes();
                    for (int i = 0; i < byteAddress.Length; i++)
                    {
                        buf[index++] = byteAddress[i];
                    }
                }
                catch (SocketException uhe)
                {
                    throw new JSchException("ProxySOCKS4: " + uhe.ToString(), uhe);
                }

                if (user != null)
                {
                    Array.Copy(user.getBytes(), 0, buf, index, user.Length);
                    index += user.Length;
                }
                buf[index++] = 0;
                Out.Write(buf, 0, index);

                /*
                   The SOCKS server checks to see whether such a request should be granted
                   based on any combination of source IP address, destination IP address,
                   destination port number, the userid, and information it may obtain by
                   consulting IDENT, cf. RFC 1413.  If the request is granted, the SOCKS
                   server makes a connection to the specified port of the destination host.
                   A reply packet is sent to the client when this connection is established,
                   or when the request is rejected or the operation fails. 
   
                               +----+----+----+----+----+----+----+----+
                               | VN | CD | DSTPORT |      DSTIP        |
                               +----+----+----+----+----+----+----+----+
                   # of bytes:   1    1      2              4
   
                   VN is the version of the reply code and should be 0. CD is the result
                   code with one of the following values:
   
                   90: request granted
                   91: request rejected or failed
                   92: request rejected becasue SOCKS server cannot connect to
                       identd on the client
                   93: request rejected because the client program and identd
                       report different user-ids
   
                   The remaining fields are ignored.
                */

                int len = 8;
                int s = 0;
                while (s < len)
                {
                    int i = In.Read(buf, s, len - s);
                    if (i <= 0)
                    {
                        throw new JSchException("ProxySOCKS4: stream is closed");
                    }
                    s += i;
                }
                if (buf[0] != 0)
                {
                    throw new JSchException("ProxySOCKS4: server returns VN " + buf[0]);
                }
                if (buf[1] != 90)
                {
                    try { socket.Close(); }
                    catch //(Exception eee)
                    {
                    }
                    string message = "ProxySOCKS4: server returns CD " + buf[1];
                    throw new JSchException(message);
                }
            }
                /*
            catch (RuntimeException e)
            {
                throw e;
            }
                 */
            catch (Exception e)
            {
                try { if (socket != null)socket.Close(); }
                catch //(Exception eee)
                {
                }
                throw new JSchException("ProxySOCKS4: " + e.Message, e);
            }
        }
        public Stream getInputStream() { return In; }
        public Stream getOutputStream() { return Out; }
        public TcpClient getSocket() { return socket; }
        public void Close()
        {
            try
            {
                if (In != null) In.Close();
                if (Out != null) Out.Close();
                if (socket != null) socket.Close();
            }
            catch //(Exception e)
            {
            }
            In = null;
            Out = null;
            socket = null;
        }
        public static int getDefaultPort()
        {
            return DEFAULTPORT;
        }
    }
}
