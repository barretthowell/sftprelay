using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.IO;
using System.Threading;

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
        private Thread me;

        public ClientServer( TcpClient client)
        {
            this.client = client;
            client.Client.Blocking = true;
            Stream s = client.GetStream();
            input = new StreamReader(s);
            output = new StreamWriter(s);
        }
        public void Start()
        {
            me = new Thread(new ThreadStart(Run));
            me.Start();
        }
        string ReadLine()
        {
            string buffer = "";
            while (running && !input.EndOfStream)
            {
                buffer += input.ReadLine();
                Console.Error.WriteLine("Buffer: " + buffer);
                break;
            }
            return buffer;
        }
        void Run()
        {
            running = true;
            Console.Error.WriteLine("Sending welcome message...");
            for (int i = 0; i < Version.WelcomeMessage.Length; i++)
            {
                output.Write("220");
                if (i < Version.WelcomeMessage.Length - 1)
                    output.Write("-");
                else
                    output.Write(" ");
                output.WriteLine(Version.WelcomeMessage[i]);
            }
            output.Flush();
            string command;
            while (running && !input.EndOfStream)
            {
                command = ReadLine();
                if (command.StartsWith("USER "))
                {
                    //USER
                    output.WriteLine("230 Whatever, not done yet");
                }
                else if (command.StartsWith("PASS "))
                {
                    output.WriteLine("230 Whatever, not done yet");
                }
                else if (command.Equals("PWD"))
                {
                    output.WriteLine("257 JE MOEDER!");
                }
                else if (command.Equals("NOOP"))
                {
                    output.WriteLine("200 Nothing happened");
                }
                else
                {
                    output.WriteLine("500 Not implemented");
                }
                output.Flush();
            }
            Console.Error.WriteLine("Client disconnected?");
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
