using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Paneidos.Relay;

namespace ConsoleRelay
{
    class Program
    {
        static RelayServer rs;
        static void Main(string[] args)
        {
            rs = new RelayServer(2100);
            Console.CancelKeyPress += new ConsoleCancelEventHandler(Console_CancelKeyPress);
            rs.Start();
        }

        static void Console_CancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            rs.Stop();
        }
    }
}
