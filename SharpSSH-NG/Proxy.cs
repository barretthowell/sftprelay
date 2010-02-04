using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;

namespace SharpSSH.NG
{
    interface Proxy
    {
        void connect(SocketFactory socket_factory, string host, int port, int timeout);
        Stream getInputStream();
        Stream getOutputStream();
        TcpClient getSocket();
        void Close();
    }
}
