using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class UserAuthPassword : UserAuth
    {
        private const int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

        public override bool start(Session session)
        {
            base.start(session);

            byte[] password = session.password;
            string dest = username + "@" + session.host;
            if (session.port != 22)
            {
                dest += (":" + session.port);
            }

            try
            {

                while (true)
                {
                    if (password == null)
                    {
                        if (userinfo == null)
                        {
                            //throw new JSchException("USERAUTH fail");
                            return false;
                        }
                        if (!userinfo.promptPassword("Password for " + dest))
                        {
                            throw new JSchAuthCancelException("password");
                            //break;
                        }

                        string _password = userinfo.getPassword();
                        if (_password == null)
                        {
                            throw new JSchAuthCancelException("password");
                            //break;
                        }
                        password = Util.str2byte(_password);
                    }

                    byte[] _username = null;
                    _username = Util.str2byte(username);

                    // send
                    // byte      SSH_MSG_USERAUTH_REQUEST(50)
                    // string    user name
                    // string    service name ("ssh-connection")
                    // string    "password"
                    // boolen    FALSE
                    // string    plaintext password (ISO-10646 UTF-8)
                    packet.reset();
                    buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
                    buf.putString(_username);
                    buf.putString("ssh-connection".getBytes());
                    buf.putString("password".getBytes());
                    buf.putByte((byte)0);
                    buf.putString(password);
                    session.write(packet);

                    while (true)
                    {
                        buf = session.Read(buf);
                        int command = buf.getCommand() & 0xff;

                        if (command == SSH_MSG_USERAUTH_SUCCESS)
                        {
                            return true;
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
                            goto loop;
                        }
                        if (command == SSH_MSG_USERAUTH_PASSWD_CHANGEREQ)
                        {
                            buf.getInt(); buf.getByte(); buf.getByte();
                            byte[] instruction = buf.getString();
                            byte[] tag = buf.getString();
                            if (userinfo == null ||
                                   !(userinfo is UIKeyboardInteractive))
                            {
                                if (userinfo != null)
                                {
                                    userinfo.showMessage("Password must be changed.");
                                }
                                return false;
                            }

                            UIKeyboardInteractive kbi = (UIKeyboardInteractive)userinfo;
                            string[] response;
                            string name = "Password Change Required";
                            string[] prompt = { "New Password: " };
                            boolean[] echo = { false };
                            response = kbi.promptKeyboardInteractive(dest,
                                                                   name,
                                                                   Encoding.UTF8.GetString(instruction),
                                                                   prompt,
                                                                   echo);
                            if (response == null)
                            {
                                throw new JSchAuthCancelException("password");
                            }

                            byte[] newpassword = response[0].getBytes();

                            // send
                            // byte      SSH_MSG_USERAUTH_REQUEST(50)
                            // string    user name
                            // string    service name ("ssh-connection")
                            // string    "password"
                            // boolen    TRUE
                            // string    plaintext old password (ISO-10646 UTF-8)
                            // string    plaintext new password (ISO-10646 UTF-8)
                            packet.reset();
                            buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
                            buf.putString(_username);
                            buf.putString("ssh-connection".getBytes());
                            buf.putString("password".getBytes());
                            buf.putByte((byte)1);
                            buf.putString(password);
                            buf.putString(newpassword);
                            Util.bzero(newpassword);
                            response = null;
                            session.write(packet);
                            goto loop;
                        }
                        if (command == SSH_MSG_USERAUTH_FAILURE)
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
                            break;
                        }
                        else
                        {
                            //Console.Error.WriteLine("USERAUTH fail ("+buf.getCommand()+")");
                            //	  throw new JSchException("USERAUTH fail ("+buf.getCommand()+")");
                            return false;
                        }
                    loop:
                        null;
                    }

                    if (password != null)
                    {
                        Util.bzero(password);
                        password = null;
                    }

                }

            }
            finally
            {
                if (password != null)
                {
                    Util.bzero(password);
                    password = null;
                }
            }

            //throw new JSchException("USERAUTH fail");
            //return false;
        }
    }
}
