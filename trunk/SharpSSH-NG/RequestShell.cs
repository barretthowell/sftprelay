using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestShell : Request
    {
        internal override void request(Session session, Channel channel)
        {
            base.request(session, channel);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);

            // send
            // byte     SSH_MSG_CHANNEL_REQUEST(98)
            // uint32 recipient channel
            // string request type       // "shell"
            // bool want reply        // 0
            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("shell".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            write(packet);
        }
    }
}
