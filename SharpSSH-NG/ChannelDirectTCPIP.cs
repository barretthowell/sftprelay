using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class ChannelDirectTCPIP : Channel
    {
        private const int LOCAL_WINDOW_SIZE_MAX = 0x20000;
        private const int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

        string host;
        int port;

        string originator_IP_address = "127.0.0.1";
        int originator_port = 0;

        ChannelDirectTCPIP() :
            base()
        {
            setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
            setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
            setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
        }

        void init()
        {
            try
            {
                io = new IO();
            }
            catch (Exception e)
            {
                System.err.println(e);
            }
        }

        public void connect()
        {
            try
            {
                Session _session = getSession();
                if (!_session.isConnected())
                {
                    throw new JSchException("session is down");
                }
                Buffer buf = new Buffer(150);
                Packet packet = new Packet(buf);
                // send
                // byte   SSH_MSG_CHANNEL_OPEN(90)
                // string channel type         //
                // uint32 sender channel       // 0
                // uint32 initial window size  // 0x100000(65536)
                // uint32 maxmum packet size   // 0x4000(16384)

                packet.reset();
                buf.putByte((byte)90);
                buf.putString("direct-tcpip".getBytes());
                buf.putInt(id);
                buf.putInt(lwsize);
                buf.putInt(lmpsize);
                buf.putString(host.getBytes());
                buf.putInt(port);
                buf.putString(originator_IP_address.getBytes());
                buf.putInt(originator_port);
                _session.write(packet);

                int retry = 1000;
                try
                {
                    while (this.getRecipient() == -1 &&
                          _session.isConnected() &&
                          retry > 0 &&
                          !eof_remote)
                    {
                        //Thread.sleep(500);
                        Thread.sleep(50);
                        retry--;
                    }
                }
                catch (Exception ee)
                {
                }
                if (!_session.isConnected())
                {
                    throw new JSchException("session is down");
                }
                if (retry == 0 || this.eof_remote)
                {
                    throw new JSchException("channel is not opened.");
                }
                /*
                if(this.eof_remote){      // failed to open
                  disconnect();
                  return;
                }
                */

                connected = true;

                if (io.In != null)
                {
                    thread = new Thread(this);
                    thread.setName("DirectTCPIP thread " + _session.getHost());
                    if (_session.daemon_thread)
                    {
                        thread.setDaemon(_session.daemon_thread);
                    }
                    thread.start();
                }
            }
            catch (Exception e)
            {
                io.close();
                io = null;
                Channel.del(this);
                if (e is JSchException)
                {
                    throw (JSchException)e;
                }
            }
        }

        public void run()
        {

            Buffer buf = new Buffer(rmpsize);
            Packet packet = new Packet(buf);
            int i = 0;

            try
            {
                Session _session = getSession();
                while (isConnected() &&
                      thread != null &&
                      io != null &&
                      io.In != null)
                {
                    i = io.In.read(buf.buffer,
                                 14,
                                 buf.buffer.length - 14
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
                    _session.write(packet, this, i);
                }
            }
            catch (Exception e)
            {
            }
            disconnect();
            //System.err.println("connect end");
        }

        public void setInputStream(InputStream In)
        {
            io.setInputStream(In);
        }
        public void setOutputStream(OutputStream Out)
        {
            io.setOutputStream(Out);
        }

        public void setHost(string host) { this.host = host; }
        public void setPort(int port) { this.port = port; }
        public void setOrgIPAddress(string foo) { this.originator_IP_address = foo; }
        public void setOrgPort(int foo) { this.originator_port = foo; }
    }
}
