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
                        try { message = new string(_message, "UTF-8"); }
                        catch (Exception e)
                        {
                            message = new string(_message);
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
                        //	  System.err.println(new string(foo)+
                        //			     " partial_success:"+(partial_success!=0));

                        if (partial_success != 0)
                        {
                            throw new JSchPartialAuthException(new string(foo));
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
                        string name = new string(buf.getString());
                        string instruction = new string(buf.getString());
                        string languate_tag = new string(buf.getString());
                        int num = buf.getInt();
                        string[] prompt = new string[num];
                        boolean[] echo = new boolean[num];
                        for (int i = 0; i < num; i++)
                        {
                            prompt[i] = new string(buf.getString());
                            echo[i] = (buf.getByte() != 0);
                        }

                        byte[][] response = null;
                        if (num > 0
                           || (name.length() > 0 || instruction.length() > 0)
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
                                    response = new byte[_response.length][];
                                    for (int i = 0; i < _response.length; i++)
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
                        //System.err.println("response.length="+response.length);
                        //else
                        //System.err.println("response is null");
                        packet.reset();
                        buf.putByte((byte)SSH_MSG_USERAUTH_INFO_RESPONSE);
                        if (num > 0 &&
                           (response == null ||  // cancel
                            num != response.length))
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
                                //System.err.println("response: |"+new string(response[i])+"| <- replace here with **** if you need");
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
