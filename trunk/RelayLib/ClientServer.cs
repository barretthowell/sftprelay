using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.IO;

namespace Paneidos.Relay
{
    
    public class ClientServer
    {
        public delegate void ClientTerminatedHandler(ClientServer cs);

        public event ClientTerminatedHandler ClientTerminated;


        private TcpClient client;
        private StreamReader input;
        private StreamWriter output;
        private bool running;

        public ClientServer( TcpClient client)
        {
            this.client = client;
            client.Client.Blocking = false;
            Stream s = client.GetStream();
            input = new StreamReader(s);
            output = new StreamWriter(s);
        }
        void ReadLine()
        {
            while (running)
            {
            }
        }
        void Run()
        {
            running = true;
            while (running)
            {
                
            }
            client.Close();
            input = null;
            output = null;
            client = null;
            ClientTerminated.Invoke(this);
        }
        public void Stop()
        {
            running = false;
        }
    }
}
