﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class RequestEnv : Request
    {
        byte[] name = new byte[0];
        byte[] value = new byte[0];
        internal void setEnv(byte[] name, byte[] value)
        {
            this.name = name;
            this.value = value;
        }
        internal override void request(Session session, Channel channel)
        {
            base.request(session, channel);

            Buffer buf = new Buffer();
            Packet packet = new Packet(buf);

            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_REQUEST);
            buf.putInt(channel.getRecipient());
            buf.putString("env".getBytes());
            buf.putByte((byte)(waitForReply() ? 1 : 0));
            buf.putString(name);
            buf.putString(value);
            write(packet);
        }
    }
}
