using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    abstract class UserAuth
    {
        //TODO: Buffer
        protected static readonly int SSH_MSG_USERAUTH_REQUEST = 50;
        protected static readonly int SSH_MSG_USERAUTH_FAILURE = 51;
        protected static readonly int SSH_MSG_USERAUTH_SUCCESS = 52;
        protected static readonly int SSH_MSG_USERAUTH_BANNER = 53;
        protected static readonly int SSH_MSG_USERAUTH_INFO_REQUEST = 60;
        protected static readonly int SSH_MSG_USERAUTH_INFO_RESPONSE = 61;
        protected static readonly int SSH_MSG_USERAUTH_PK_OK = 60;

        protected UserInfo userinfo;
        protected Packet packet;
        protected Buffer buf;
        protected string username;

        public bool start(Session session)
        {
            this.userinfo = session.getUserInfo();
            this.packet = session.packet;
            this.buf = packet.getBuffer();
            this.username = session.getUserName();
            return true;
        }
    }
}
