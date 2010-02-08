using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestX11 : Request
    {
        public void setCookie(string cookie)
        {
            ChannelX11.cookie = cookie.getBytes();
        }
        internal override void request(Session session, Channel channel)
        {
            base.request(session, channel);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);

            // byte      SSH_MSG_CHANNEL_REQUEST(98)
            // uint32 recipient channel
            // string request type        // "x11-req"
            // bool want reply         // 0
            // bool   single connection
            // string    x11 authentication protocol // "MIT-MAGIC-COOKIE-1".
            // string    x11 authentication cookie
            // uint32    x11 screen number
            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("x11-req".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            buf.putByte((byte)0);
            buf.putString("MIT-MAGIC-COOKIE-1".getBytes());
            buf.putString(ChannelX11.getFakedCookie(session));
            buf.putInt(0);
            write(packet);

            session.x11_forwarding = true;
        }
    }
}
