﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestSftp : Request
    {
        internal RequestSftp()
        {
            setReply(true);
        }
        internal override void request(Session session, Channel channel)
        {
            base.request(session, channel);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);
            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("subsystem".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            buf.putString("sftp".getBytes());
            write(packet);
        }
    }
}
