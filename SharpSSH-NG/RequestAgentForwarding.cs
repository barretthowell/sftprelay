using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestAgentForwarding : Request
    {
        public void request(Session session, Channel channel)
        {
            base.request(session, channel);

            setReply(false);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);

            // byte      SSH_MSG_CHANNEL_REQUEST(98)
            // uint32 recipient channel
            // string request type        // "auth-agent-req@openssh.com"
            // bool want reply         // 0
            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("auth-agent-req@openssh.com".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            write(packet);
            session.agent_forwarding = true;
        }
    }
}
