using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class UserAuthPublicKey : UserAuth
    {

        public override bool start(Session session)
        {
            base.start(session);

            Vector identities = session.jsch.identities;

            byte[] passphrase = null;
            byte[] _username = null;

            int command;

            lock (identities)
            {
                if (identities.Count <= 0)
                {
                    return false;
                }

                _username = Util.str2byte(username);

                for (int i = 0; i < identities.Count; i++)
                {
                    Identity identity = identities[i];
                    byte[] pubkeyblob = identity.getPublicKeyBlob();

                    //Console.Error.WriteLine("UserAuthPublicKey: "+identity+" "+pubkeyblob);

                    if (pubkeyblob != null)
                    {
                        // send
                        // byte      SSH_MSG_USERAUTH_REQUEST(50)
                        // string    user name
                        // string    service name ("ssh-connection")
                        // string    "publickey"
                        // boolen    FALSE
                        // string    plaintext password (ISO-10646 UTF-8)
                        packet.reset();
                        buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
                        buf.putString(_username);
                        buf.putString("ssh-connection".getBytes());
                        buf.putString("publickey".getBytes());
                        buf.putByte((byte)0);
                        buf.putString(identity.getAlgName().getBytes());
                        buf.putString(pubkeyblob);
                        session.write(packet);

                        while (true)
                        {
                            buf = session.read(buf);
                            command = buf.getCommand() & 0xff;

                            if (command == SSH_MSG_USERAUTH_PK_OK)
                            {
                                break;
                            }
                            else if (command == SSH_MSG_USERAUTH_FAILURE)
                            {
                                break;
                            }
                            else if (command == SSH_MSG_USERAUTH_BANNER)
                            {
                                buf.getInt(); buf.getByte(); buf.getByte();
                                byte[] _message = buf.getString();
                                byte[] lang = buf.getString();
                                string message = null;
                                try { message = Encoding.UTF8.GetString(_message); }
                                catch (java.io.UnsupportedEncodingException e)
                                {
                                    message = Encoding.UTF8.GetString(_message);
                                }
                                if (userinfo != null)
                                {
                                    userinfo.showMessage(message);
                                }
                                goto loop1;
                            }
                            else
                            {
                                //Console.Error.WriteLine("USERAUTH fail ("+command+")");
                                //throw new JSchException("USERAUTH fail ("+command+")");
                                break;
                            }
                        loop1:
                            null;
                        }

                        if (command != SSH_MSG_USERAUTH_PK_OK)
                        {
                            continue;
                        }
                    }

                    //Console.Error.WriteLine("UserAuthPublicKey: identity.isEncrypted()="+identity.isEncrypted());

                    int count = 5;
                    while (true)
                    {
                        if ((identity.isEncrypted() && passphrase == null))
                        {
                            if (userinfo == null) throw new JSchException("USERAUTH fail");
                            if (identity.isEncrypted() &&
                               !userinfo.promptPassphrase("Passphrase for " + identity.getName()))
                            {
                                throw new JSchAuthCancelException("publickey");
                                //throw new JSchException("USERAUTH cancel");
                                //break;
                            }
                            string _passphrase = userinfo.getPassphrase();
                            if (_passphrase != null)
                            {
                                passphrase = Util.str2byte(_passphrase);
                            }
                        }

                        if (!identity.isEncrypted() || passphrase != null)
                        {
                            if (identity.setPassphrase(passphrase))
                                break;
                        }
                        Util.bzero(passphrase);
                        passphrase = null;
                        count--;
                        if (count == 0) break;
                    }

                    Util.bzero(passphrase);
                    passphrase = null;
                    //Console.Error.WriteLine("UserAuthPublicKey: identity.isEncrypted()="+identity.isEncrypted());

                    if (identity.isEncrypted()) continue;
                    if (pubkeyblob == null) pubkeyblob = identity.getPublicKeyBlob();

                    //Console.Error.WriteLine("UserAuthPublicKey: pubkeyblob="+pubkeyblob);

                    if (pubkeyblob == null) continue;

                    // send
                    // byte      SSH_MSG_USERAUTH_REQUEST(50)
                    // string    user name
                    // string    service name ("ssh-connection")
                    // string    "publickey"
                    // boolen    TRUE
                    // string    plaintext password (ISO-10646 UTF-8)
                    packet.reset();
                    buf.putByte((byte)SSH_MSG_USERAUTH_REQUEST);
                    buf.putString(_username);
                    buf.putString("ssh-connection".getBytes());
                    buf.putString("publickey".getBytes());
                    buf.putByte((byte)1);
                    buf.putString(identity.getAlgName().getBytes());
                    buf.putString(pubkeyblob);

                    //      byte[] tmp=new byte[buf.index-5];
                    //      Array.Copy(buf.buffer, 5, tmp, 0, tmp.Length);
                    //      buf.putString(signature);

                    byte[] sid = session.getSessionId();
                    int sidlen = sid.Length;
                    byte[] tmp = new byte[4 + sidlen + buf.index - 5];
                    tmp[0] = (byte)(((uint)sidlen) >> 24);
                    tmp[1] = (byte)(((uint)sidlen) >> 16);
                    tmp[2] = (byte)(((uint)sidlen) >> 8);
                    tmp[3] = (byte)(sidlen);
                    Array.Copy(sid, 0, tmp, 4, sidlen);
                    Array.Copy(buf.buffer, 5, tmp, 4 + sidlen, buf.index - 5);
                    byte[] signature = identity.getSignature(tmp);
                    if (signature == null)
                    {  // for example, too long key length.
                        break;
                    }
                    buf.putString(signature);
                    session.write(packet);

                    while (true)
                    {
                        buf = session.read(buf);
                        command = buf.getCommand() & 0xff;

                        if (command == SSH_MSG_USERAUTH_SUCCESS)
                        {
                            return true;
                        }
                        else if (command == SSH_MSG_USERAUTH_BANNER)
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
                            goto loop2;
                        }
                        else if (command == SSH_MSG_USERAUTH_FAILURE)
                        {
                            buf.getInt(); buf.getByte(); buf.getByte();
                            byte[] foo = buf.getString();
                            int partial_success = buf.getByte();
                            //Console.Error.WriteLine(Encoding.UTF8.GetString(foo)+
                            //                   " partial_success:"+(partial_success!=0));
                            if (partial_success != 0)
                            {
                                throw new JSchPartialAuthException(Encoding.UTF8.GetString(foo));
                            }
                            break;
                        }
                        //Console.Error.WriteLine("USERAUTH fail ("+command+")");
                        //throw new JSchException("USERAUTH fail ("+command+")");
                        break;
                    loop2:
                        null;
                    }
                }
            }
            return false;
        }
    }
}
