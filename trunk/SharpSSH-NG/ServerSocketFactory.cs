using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;

namespace SharpSSH.NG
{
    interface ServerSocketFactory
    {
        TcpListener createServerSocket(int port, int backlog, IPAddress bindAddr);
    }
}
