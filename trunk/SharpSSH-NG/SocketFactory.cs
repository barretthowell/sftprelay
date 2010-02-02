using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.IO;

namespace SharpSSH.NG
{
    interface SocketFactory
    {
        TcpClient createSocket(string host, int port);
        Stream getInputStream(TcpClient socket);
        Stream getOutputStream(TcpClient socket);
    }
}
