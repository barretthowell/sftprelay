using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.Threading;

namespace Paneidos.Relay
{
    public class RelayServer
    {
        private const int DefaultPort = 2121;
        private static readonly IPAddress DefaultAddress = null;
        private bool running = false;
        private Thread serverThread;

        public int Port { get { return localEP.Port; } }
        public IPAddress Address { get { return localEP.Address; } }
        public AddressFamily AddressFamily { get { return localEP.AddressFamily; } }
        
        private IPEndPoint localEP;
        private TcpListener serverSocket;
        private List<ClientServer> pool = new List<ClientServer>();

        static RelayServer()
        {
            RelayServer.DefaultAddress = IPAddress.Loopback;
        }
        public RelayServer()
            : this(new IPEndPoint(DefaultAddress, DefaultPort))
        {
        }

        public RelayServer(int port)
            : this(new IPEndPoint(DefaultAddress, port))
        {
            
        }
        public RelayServer(IPAddress address, int port)
            : this(new IPEndPoint(address, port))
        {
        }
        public RelayServer(IPEndPoint localEP)
        {
            this.localEP = localEP;
        }
        public void Start()
        {
            serverThread = new Thread(new ThreadStart(Run));
            serverThread.Start();
        }
        public void Stop()
        {
            running = false;
            serverThread.Join();
        }
        void Run()
        {
            ClientServer curCS;
            running = true;
            serverSocket = new TcpListener(localEP);
            serverSocket.Start();
            while (running)
            {
                while (running && !serverSocket.Pending())
                {
                    Thread.Sleep(100);
                }
                if (!running) break;
                Console.Error.WriteLine("New client");
                curCS = new ClientServer(serverSocket.AcceptTcpClient());
                curCS.ClientTerminated += new ClientServer.ClientTerminatedHandler(curCS_ClientTerminated);
                pool.Add(curCS);
                curCS.Start();
            }
            serverSocket.Stop();
            for (int i = pool.Count - 1; i >= 0; i--)
            {
                pool[i].Stop();
            }
        }

        void curCS_ClientTerminated(ClientServer cs)
        {
            //TODO
        }

    }
}
