using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.IO;

namespace SharpSSH.NG
{
    class ProxyHTTP : Proxy
    {
        private static int DEFAULTPORT = 80;
        private string proxy_host;
        private int proxy_port;
        private Stream In;
        private Stream Out;
        private TcpClient socket;

        private string user;
        private string passwd;

        public ProxyHTTP(string proxy_host)
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
                catch (Exception e)
                {
                }
            }
            this.proxy_host = host;
            this.proxy_port = port;
        }
        public ProxyHTTP(string proxy_host, int proxy_port)
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
                    In = socket.getInputStream();
                    Out = socket.getOutputStream();
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
                socket.NoDelay = true;

                Out.Write(("CONNECT " + host + ":" + port + " HTTP/1.0\r\n").getBytes());

                if (user != null && passwd != null)
                {
                    byte[] code = (user + ":" + passwd).getBytes();
                    code = Util.toBase64(code, 0, code.Length);
                    Out.write("Proxy-Authorization: Basic ".getBytes());
                    Out.write(code);
                    Out.write("\r\n".getBytes());
                }

                Out.write("\r\n".getBytes());
                Out.flush();

                int foo = 0;

                StringBuilder sb = new StringBuilder();
                while (foo >= 0)
                {
                    foo = In.Read(); if (foo != 13) { sb.append((char)foo); continue; }
                    foo = In.Read(); if (foo != 10) { continue; }
                    break;
                }
                if (foo < 0)
                {
                    throw new IOException();
                }

                string response = sb.ToString();
                string reason = "Unknow reason";
                int code = -1;
                try
                {
                    foo = response.IndexOf(' ');
                    int bar = response.IndexOf(' ', foo + 1);
                    code = int.Parse(response.Substring(foo + 1, bar - (foo+1)));
                    reason = response.Substring(bar + 1);
                }
                catch (Exception e)
                {
                }
                if (code != 200)
                {
                    throw new IOException("proxy error: " + reason);
                }

                /*
                while(foo>=0){
                  foo=In.Read(); if(foo!=13) continue;
                  foo=In.Read(); if(foo!=10) continue;
                  foo=In.Read(); if(foo!=13) continue;      
                  foo=In.Read(); if(foo!=10) continue;
                  break;
                }
                */

                int count = 0;
                while (true)
                {
                    count = 0;
                    while (foo >= 0)
                    {
                        foo = In.Read(); if (foo != 13) { count++; continue; }
                        foo = In.Read(); if (foo != 10) { continue; }
                        break;
                    }
                    if (foo < 0)
                    {
                        throw new IOException();
                    }
                    if (count == 0) break;
                }
            }
            catch (Exception e)
            {
                try { if (socket != null)socket.Close(); }
                catch (Exception eee)
                {
                }
                string message = "ProxyHTTP: " + e.ToString();
                throw new JSchException(message,e);
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
            catch (Exception e)
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
