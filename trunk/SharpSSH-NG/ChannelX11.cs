using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading;
using System.IO;

namespace SharpSSH.NG
{
    class ChannelX11 : Channel
    {
        private const int LOCAL_WINDOW_SIZE_MAX = 0x20000;
        private const int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

        private const int TIMEOUT = 10 * 1000;

        private static string host = "127.0.0.1";
        private static int port = 6000;

        private bool _init = true;

        internal static byte[] cookie = null;
        private static byte[] cookie_hex = null;

        private static Dictionary<Session,byte[]> faked_cookie_pool = new Dictionary<Session,byte[]>();
        private static Dictionary<Session, byte[]> faked_cookie_hex_pool = new Dictionary<Session,byte[]>();

        private static byte[] table ={0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
                               0x61,0x62,0x63,0x64,0x65,0x66};

        private TcpClient socket = null;

        internal static int revtable(byte foo)
        {
            for (int i = 0; i < table.Length; i++)
            {
                if (table[i] == foo) return i;
            }
            return 0;
        }
        internal static void setCookie(string foo)
        {
            cookie_hex = foo.getBytes();
            cookie = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                cookie[i] = (byte)(((revtable(cookie_hex[i * 2]) << 4) & 0xf0) |
                         ((revtable(cookie_hex[i * 2 + 1])) & 0xf));
            }
        }
        internal static void setHost(string foo) { host = foo; }
        internal static void setPort(int foo) { port = foo; }
        internal static byte[] getFakedCookie(Session session)
        {
            lock (faked_cookie_hex_pool)
            {
                byte[] foo = faked_cookie_hex_pool[session] ;
                if (foo == null)
                {
                    Random random = Session.random;
                    foo = new byte[16];
                    lock (random)
                    {
                        random.fill(foo, 0, 16);
                    }
                    /*
                    System.err.print("faked_cookie: ");
                    for(int i=0; i<foo.Length; i++){
                        System.err.print(Integer.toHexString(foo[i]&0xff)+":");
                    }
                    Console.Error.WriteLine("");
                    */
                    faked_cookie_pool.Add(session, foo);
                    byte[] bar = new byte[32];
                    for (int i = 0; i < 16; i++)
                    {
                        bar[2 * i] = table[(foo[i] >> 4) & 0xf];
                        bar[2 * i + 1] = table[(foo[i]) & 0xf];
                    }
                    faked_cookie_hex_pool.Add(session, bar);
                    foo = bar;
                }
                return foo;
            }
        }

        internal ChannelX11()
            : base()
        {

            setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
            setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
            setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);

            type = "x11".getBytes();

            connected = true;
            /*
            try{ 
              socket=Util.createSocket(host, port, TIMEOUT);
              socket.NoDelay=true;
              io=new IO();
              io.setInputStream(socket.GetStream());
              io.setOutputStream(socket.GetStream());
            }
            catch(Exception e){
              //Console.Error.WriteLine(e);
            }
            */
        }

        public override void run()
        {

            try
            {
                socket = Util.createSocket(host, port, TIMEOUT);
                socket.NoDelay=true;
                io = new IO();
                io.setInputStream(socket.GetStream());
                io.setOutputStream(socket.GetStream());
                sendOpenConfirmation();
            }
            catch //(Exception e)
            {
                sendOpenFailure(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
                close = true;
                disconnect();
                return;
            }

            thread = Thread.CurrentThread;
            Buffer buf = new Buffer(rmpsize);
            Packet packet = new Packet(buf);
            int i = 0;
            try
            {
                while (thread != null &&
                      io != null &&
                      io.In != null)
                {
                    i = io.In.Read(buf.buffer,
                         14,
                         buf.buffer.Length - 14
                         - 32 - 20 // padding and mac
                         );
                    if (i <= 0)
                    {
                        eof();
                        break;
                    }
                    if (close) break;
                    packet.reset();
                    buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
                    buf.putInt(recipient);
                    buf.putInt(i);
                    buf.skip(i);
                    getSession().write(packet, this, i);
                }
            }
            catch //(Exception e)
            {
                //Console.Error.WriteLine(e);
            }
            disconnect();
        }

        private byte[] cache = new byte[0];
        private byte[] addCache(byte[] foo, int s, int l)
        {
            byte[] bar = new byte[cache.Length + l];
            Array.Copy(foo, s, bar, cache.Length, l);
            if (cache.Length > 0)
                Array.Copy(cache, 0, bar, 0, cache.Length);
            cache = bar;
            return cache;
        }

        internal override void write(byte[] foo, int s, int l)
        {
            //if(eof_local)return;

            if (_init)
            {

                Session _session = null;
                try
                {
                    _session = getSession();
                }
                catch (JSchException e)
                {
                    throw new IOException(e.Message,e);
                }

                foo = addCache(foo, s, l);
                s = 0;
                l = foo.Length;

                if (l < 9)
                    return;

                uint plen = unchecked( (uint) ( (foo[s + 6] & 0xff) * 256 + (foo[s + 7] & 0xff)));
                uint dlen =unchecked( (uint) ((foo[s + 8] & 0xff) * 256 + (foo[s + 9] & 0xff)));

                if ((foo[s] & 0xff) == 0x42)
                {
                }
                else if ((foo[s] & 0xff) == 0x6c)
                {
                    plen = ((plen >> 8) & 0xff) | ((plen << 8) & 0xff00);
                    dlen = ((dlen >> 8) & 0xff) | ((dlen << 8) & 0xff00);
                }
                else
                {
                    // ??
                }

                if (l < 12 + plen + ((-plen) & 3) + dlen)
                    return;

                byte[] bar = new byte[dlen];
                Array.Copy(foo, s + 12 + plen + ((-plen) & 3), bar, 0, dlen);
                byte[] faked_cookie = null;

                lock (faked_cookie_pool)
                {
                    faked_cookie = faked_cookie_pool[_session];
                }

                /*
          System.err.print("faked_cookie: ");
          for(int i=0; i<faked_cookie.Length; i++){
              System.err.print(Integer.toHexString(faked_cookie[i]&0xff)+":");
          }
          Console.Error.WriteLine("");
          System.err.print("bar: ");
          for(int i=0; i<bar.Length; i++){
              System.err.print(Integer.toHexString(bar[i]&0xff)+":");
          }
          Console.Error.WriteLine("");
                */

                if (equals(bar, faked_cookie))
                {
                    if (cookie != null)
                        Array.Copy(cookie, 0, foo, s + 12 + plen + ((-plen) & 3), dlen);
                }
                else
                {
                    //Console.Error.WriteLine("wrong cookie");
                    thread = null;
                    eof();
                    io.Close();
                    disconnect();
                }
                _init = false;
                io.put(foo, s, l);
                cache = null;
                return;
            }
            io.put(foo, s, l);
        }

        private static bool equals(byte[] foo, byte[] bar)
        {
            if (foo.Length != bar.Length) return false;
            for (int i = 0; i < foo.Length; i++)
            {
                if (foo[i] != bar[i]) return false;
            }
            return true;
        }
    }
}

