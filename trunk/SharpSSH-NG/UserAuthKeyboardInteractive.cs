using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class UserAuthKeyboardInteractive : UserAuth
    {
        public bool start(Session session)
        {
            base.start(session);

            if (userinfo != null && !(userinfo is UIKeyboardInteractive))
            {
                return false;
            }

            string dest = username + "@" + session.host;
            if (session.port != 22)
            {
                dest += (":" + session.port);
            }
            byte[] password = session.password;

            bool cancel = false;

            byte[] _username = null;
            _username = Util.str2byte(username);

            while (true)
            {
                // send
                // byte      SSH_MSG_USERAUTH_REQUEST(50)
                // string    user name (ISO-10646 UTF-8, as defined in [RFC-2279])
                // string    service name (US-ASCII) "ssh-userauth" ? "ssh-connection"
                // string    "keyboard-interactive" (US-ASCII)
                // string    language tag (as defined in [RFC-3066])
                // string    submethods (ISO-10646 UTF-8)
                packet.reset();
                buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
                buf.putString(_username);
                buf.putString("ssh-connection".getBytes());
                //buf.putString("ssh-userauth".getBytes());
                buf.putString("keyboard-interactive".getBytes());
                buf.putString("".getBytes());
                buf.putString("".getBytes());
                session.write(packet);

                bool firsttime = true;
                while (true)
                {
                    buf = session.read(buf);
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
                        string message = null;
                        try { message = Encoding.UTF8.GetString(_message); }
                        catch (Exception e)
                        {
                            message = Encoding.UTF8.GetString(_message);
                        }
                        if (userinfo != null)
                        {
                            userinfo.showMessage(message);
                        }
                        goto loop;
                    }
                    if (command == SSH_MSG_USERAUTH_FAILURE)
                    {
                        buf.getInt(); buf.getByte(); buf.getByte();
                        byte[] foo = buf.getString();
                        int partial_success = buf.getByte();
                        //	  Console.Error.WriteLine(Encoding.UTF8.GetString(foo)+
                        //			     " partial_success:"+(partial_success!=0));

                        if (partial_success != 0)
                        {
                            throw new JSchPartialAuthException(Encoding.UTF8.GetString(foo));
                        }

                        if (firsttime)
                        {
                            return false;
                            //throw new JSchException("USERAUTH KI is not supported");
                            //cancel=true;  // ??
                        }
                        break;
                    }
                    if (command == SSH_MSG_USERAUTH_INFO_REQUEST)
                    {
                        firsttime = false;
                        buf.getInt(); buf.getByte(); buf.getByte();
                        string name = Encoding.UTF8.GetString(buf.getString());
                        string instruction = Encoding.UTF8.GetString(buf.getString());
                        string languate_tag = Encoding.UTF8.GetString(buf.getString());
                        int num = buf.getInt();
                        string[] prompt = new string[num];
                        boolean[] echo = new boolean[num];
                        for (int i = 0; i < num; i++)
                        {
                            prompt[i] = Encoding.UTF8.GetString(buf.getString());
                            echo[i] = (buf.getByte() != 0);
                        }

                        byte[][] response = null;
                        if (num > 0
                           || (name.Length > 0 || instruction.Length > 0)
                           )
                        {
                            if (userinfo != null)
                            {
                                UIKeyboardInteractive kbi = (UIKeyboardInteractive)userinfo;
                                string[] _response = kbi.promptKeyboardInteractive(dest,
                                                                                 name,
                                                                                 instruction,
                                                                                 prompt,
                                                                                 echo);
                                if (_response != null)
                                {
                                    response = new byte[_response.Length][];
                                    for (int i = 0; i < _response.Length; i++)
                                    {
                                        response[i] = Util.str2byte(_response[i]);
                                    }
                                }
                            }
                            else if (password != null &&
                                        prompt.Length == 1 &&
                                        !echo[0] &&
                                        prompt[0].ToLower().StartsWith("password:"))
                            {
                                response = new byte[1][];
                                response[0] = password;
                                password = null;
                            }
                        }

                        // byte      SSH_MSG_USERAUTH_INFO_RESPONSE(61)
                        // int       num-responses
                        // string    response[1] (ISO-10646 UTF-8)
                        // ...
                        // string    response[num-responses] (ISO-10646 UTF-8)
                        //if(response!=null)
                        //Console.Error.WriteLine("response.Length="+response.Length);
                        //else
                        //Console.Error.WriteLine("response is null");
                        packet.reset();
                        buf.putByte((byte)SSH_MSG_USERAUTH_INFO_RESPONSE);
                        if (num > 0 &&
                           (response == null ||  // cancel
                            num != response.Length))
                        {

                            if (response == null)
                            {
                                // working around the bug in OpenSSH ;-<
                                buf.putInt(num);
                                for (int i = 0; i < num; i++)
                                {
                                    buf.putString("".getBytes());
                                }
                            }
                            else
                            {
                                buf.putInt(0);
                            }

                            if (response == null)
                                cancel = true;
                        }
                        else
                        {
                            buf.putInt(num);
                            for (int i = 0; i < num; i++)
                            {
                                //Console.Error.WriteLine("response: |"+Encoding.UTF8.GetString(response[i])+"| <- replace here with **** if you need");
                                buf.putString(response[i]);
                            }
                        }
                        session.write(packet);
                        /*
                    if(cancel)
                      break;
                        */
                        goto loop;
                    }
                    //throw new JSchException("USERAUTH fail ("+command+")");
                    return false;
                loop:
                    null;
                }
                if (cancel)
                {
                    throw new JSchAuthCancelException("keyboard-interactive");
                    //break;
                }
            }
            //return false;
        }
    }
}
