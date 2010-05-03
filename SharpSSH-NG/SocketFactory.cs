using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.IO;

namespace SharpSSH.NG
{
    public interface SocketFactory
    {
        TcpClient createSocket(string host, int port);
        Stream GetStream(TcpClient socket);
    }
}
