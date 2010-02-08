using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class UserAuthNone : UserAuth
    {
        private const int SSH_MSG_SERVICE_ACCEPT = 6;
        private string methods = null;

        public override bool start(Session session)
        {
            base.start(session);


            // send
            // byte      SSH_MSG_SERVICE_REQUEST(5)
            // string    service name "ssh-userauth"
            packet.reset();
            buf.putByte((byte)Session.SSH_MSG_SERVICE_REQUEST);
            buf.putString("ssh-userauth".getBytes());
            session.write(packet);

            if (JSch.getLogger().isEnabled(Logger.INFO))
            {
                JSch.getLogger().log(Logger.INFO,
                                     "SSH_MSG_SERVICE_REQUEST sent");
            }

            // receive
            // byte      SSH_MSG_SERVICE_ACCEPT(6)
            // string    service name
            buf = session.Read(buf);
            int command = buf.getCommand();

            bool result = (command == SSH_MSG_SERVICE_ACCEPT);

            if (JSch.getLogger().isEnabled(Logger.INFO))
            {
                JSch.getLogger().log(Logger.INFO,
                                     "SSH_MSG_SERVICE_ACCEPT received");
            }
            if (!result)
                return false;

            byte[] _username = null;
            _username = Util.str2byte(username);

            // send
            // byte      SSH_MSG_USERAUTH_REQUEST(50)
            // string    user name
            // string    service name ("ssh-connection")
            // string    "none"
            packet.reset();
            buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
            buf.putString(_username);
            buf.putString("ssh-connection".getBytes());
            buf.putString("none".getBytes());
            session.write(packet);

            while (true)
            {
                buf = session.Read(buf);
                command = buf.getCommand() & 0xff;

                if (command == SSH_MSG_USERAUTH_SUCCESS)
                {
                    return true;
                }
                if (command == SSH_MSG_USERAUTH_BANNER)
                {
                    buf.getInt(); buf.getByte(); buf.getByte();
                    byte[] _message = buf.getString();
                    byte[] lang = buf.getString();
                    string message = null;
                    
                    //try
                    //{
                        message = Encoding.UTF8.GetString(_message);
                    //}
                    //catch (DecoderFallbackException e)
                    //{
                    //    message = Encoding.UTF8.GetString(_message);
                    //}
                    if (userinfo != null)
                    {
                        //try
                        //{
                            userinfo.showMessage(message);
                        //}
                        //catch (RuntimeException ee)
                        //{
                        //}
                    }
                    goto loop;
                }
                if (command == SSH_MSG_USERAUTH_FAILURE)
                {
                    buf.getInt(); buf.getByte(); buf.getByte();
                    byte[] foo = buf.getString();
                    int partial_success = buf.getByte();
                    methods = Encoding.UTF8.GetString(foo);
                    //Console.Error.WriteLine("UserAuthNONE: "+methods+
                    //		   " partial_success:"+(partial_success!=0));
                    //	if(partial_success!=0){
                    //	  throw new JSchPartialAuthException(Encoding.UTF8.GetString(foo));
                    //	}

                    break;
                }
                else
                {
                    //      Console.Error.WriteLine("USERAUTH fail ("+command+")");
                    throw new JSchException("USERAUTH fail (" + command + ")");
                }
            loop:
                new object();
            }
            //throw new JSchException("USERAUTH fail");
            return false;
        }
        internal string getMethods()
        {
            return methods;
        }
    }
}
