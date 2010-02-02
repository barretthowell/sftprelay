using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestExec : Request
    {
        private byte[] command = new byte[0];
        RequestExec(byte[] command)
        {
            this.command = command;
        }
        public void request(Session session, Channel channel)
        {
            base.request(session, channel);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);

            // send
            // byte     SSH_MSG_CHANNEL_REQUEST(98)
            // uint32 recipient channel
            // string request type       // "exec"
            // bool want reply        // 0
            // string command
            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("exec".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            buf.putString(command);
            write(packet);
        }
    }
}
