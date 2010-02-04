using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestPtyReq : Request
    {
        private string ttype = "vt100";
        private int tcol = 80;
        private int trow = 24;
        private int twp = 640;
        private int thp = 480;

        private byte[] terminal_mode = "".getBytes();

        void setCode(string cookie)
        {
        }

        internal void setTType(string ttype)
        {
            this.ttype = ttype;
        }

        internal void setTerminalMode(byte[] terminal_mode)
        {
            this.terminal_mode = terminal_mode;
        }

        internal void setTSize(int tcol, int trow, int twp, int thp)
        {
            this.tcol = tcol;
            this.trow = trow;
            this.twp = twp;
            this.thp = thp;
        }

        public void request(Session session, Channel channel)
        {
            base.request(session, channel);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);

            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("pty-req".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            buf.putString(ttype.getBytes());
            buf.putInt(tcol);
            buf.putInt(trow);
            buf.putInt(twp);
            buf.putInt(thp);
            buf.putString(terminal_mode);
            write(packet);
        }
    }
}
