using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class UserAuthGSSAPIWithMIC : UserAuth
    {
        private const int SSH_MSG_USERAUTH_GSSAPI_RESPONSE = 60;
        private const int SSH_MSG_USERAUTH_GSSAPI_TOKEN = 61;
        private const int SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE = 63;
        private const int SSH_MSG_USERAUTH_GSSAPI_ERROR = 64;
        private const int SSH_MSG_USERAUTH_GSSAPI_ERRTOK = 65;
        private const int SSH_MSG_USERAUTH_GSSAPI_MIC = 66;

        private static readonly byte[,] supported_oid ={
    // OID 1.2.840.113554.1.2.2 in DER
    {(byte)0x6,(byte)0x9,(byte)0x2a,(byte)0x86,(byte)0x48,
     (byte)0x86,(byte)0xf7,(byte)0x12,(byte)0x1,(byte)0x2,
     (byte)0x2}
  };

        private static readonly string[] supported_method ={
    "gssapi-with-mic.krb5"
  };

        public override bool start(Session session)
        {
            base.start(session);

            byte[] _username = Util.str2byte(username);

            packet.reset();

            // byte            SSH_MSG_USERAUTH_REQUEST(50)
            // string          user name(in ISO-10646 UTF-8 encoding)
            // string          service name(in US-ASCII)
            // string          "gssapi"(US-ASCII)
            // uint32          n, the number of OIDs client supports
            // string[n]       mechanism OIDS
            buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
            buf.putString(_username);
            buf.putString("ssh-connection".getBytes());
            buf.putString("gssapi-with-mic".getBytes());
            buf.putInt(supported_oid.Length);
            for (int i = 0; i < supported_oid.Length; i++)
            {
                buf.putString(supported_oid.getRow(i));
            }
            session.write(packet);

            string method = null;
            int command;
            while (true)
            {
                buf = session.Read(buf);
                command = buf.getCommand() & 0xff;

                if (command == SSH_MSG_USERAUTH_FAILURE)
                {
                    return false;
                }

                if (command == SSH_MSG_USERAUTH_GSSAPI_RESPONSE)
                {
                    buf.getInt(); buf.getByte(); buf.getByte();
                    byte[] message = buf.getString();

                    for (int i = 0; i < supported_oid.Length; i++)
                    {
                        if (Util.array_equals(message, supported_oid.getRow(i)))
                        {
                            method = supported_method[i];
                            break;
                        }
                    }

                    if (method == null)
                    {
                        return false;
                    }

                    break; // success
                }

                if (command == SSH_MSG_USERAUTH_BANNER)
                {
                    buf.getInt(); buf.getByte(); buf.getByte();
                    byte[] _message = buf.getString();
                    byte[] lang = buf.getString();
                    string message = Util.byte2str(_message);
                    if (userinfo != null)
                    {
                        userinfo.showMessage(message);
                    }
                    continue;
                }
                return false;
            }

            GSSContext context = null;
            try
            {
                Type c = Type.GetType(session.getConfig(method));
                context = (GSSContext)(c.newInstance());
            }
            catch //(Exception e)
            {
                return false;
            }

            try
            {
                context.create(username, session.host);
            }
            catch (JSchException )
            {
                return false;
            }

            byte[] token = new byte[0];

            while (!context.isEstablished())
            {
                try
                {
                    token = context.init(token, 0, token.Length);
                }
                catch (JSchException )
                {
                    // TODO
                    // ERRTOK should be sent?
                    // byte        SSH_MSG_USERAUTH_GSSAPI_ERRTOK
                    // string      error token
                    return false;
                }

                if (token != null)
                {
                    packet.reset();
                    buf.putByte((byte)SSH_MSG_USERAUTH_GSSAPI_TOKEN);
                    buf.putString(token);
                    session.write(packet);
                }

                if (!context.isEstablished())
                {
                    buf = session.Read(buf);
                    command = buf.getCommand() & 0xff;
                    if (command == SSH_MSG_USERAUTH_GSSAPI_ERROR)
                    {
                        // uint32    major_status
                        // uint32    minor_status
                        // string    message
                        // string    language tag

                        buf = session.Read(buf);
                        command = buf.getCommand() & 0xff;
                        //return false;
                    }
                    else if (command == SSH_MSG_USERAUTH_GSSAPI_ERRTOK)
                    {
                        // string error token

                        buf = session.Read(buf);
                        command = buf.getCommand() & 0xff;
                        //return false;
                    }

                    if (command == SSH_MSG_USERAUTH_FAILURE)
                    {
                        return false;
                    }

                    buf.getInt(); buf.getByte(); buf.getByte();
                    token = buf.getString();
                }
            }

            Buffer mbuf = new Buffer();
            // string    session identifier
            // byte      SSH_MSG_USERAUTH_REQUEST
            // string    user name
            // string    service
            // string    "gssapi-with-mic"
            mbuf.putString(session.getSessionId());
            mbuf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
            mbuf.putString(_username);
            mbuf.putString("ssh-connection".getBytes());
            mbuf.putString("gssapi-with-mic".getBytes());

            byte[] mic = context.getMIC(mbuf.buffer, 0, mbuf.getLength());

            if (mic == null)
            {
                return false;
            }

            packet.reset();
            buf.putByte((byte)SSH_MSG_USERAUTH_GSSAPI_MIC);
            buf.putString(mic);
            session.write(packet);

            context.dispose();

            buf = session.Read(buf);
            command = buf.getCommand() & 0xff;

            if (command == SSH_MSG_USERAUTH_SUCCESS)
            {
                return true;
            }
            else if (command == SSH_MSG_USERAUTH_FAILURE)
            {
                buf.getInt(); buf.getByte(); buf.getByte();
                byte[] foo = buf.getString();
                int partial_success = buf.getByte();
                //Console.Error.WriteLine(Encoding.UTF8.GetString(foo)+
                //		 " partial_success:"+(partial_success!=0));
                if (partial_success != 0)
                {
                    throw new JSchPartialAuthException(Encoding.UTF8.GetString(foo));
                }
            }
            return false;
        }
    }
}
