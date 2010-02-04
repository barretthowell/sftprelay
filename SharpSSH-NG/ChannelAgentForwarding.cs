using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SharpSSH.NG
{
    class ChannelAgentForwarding : Channel
    {
        private const int LOCAL_WINDOW_SIZE_MAX = 0x20000;
        private const int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

        private const int SSH2_AGENTC_REQUEST_IDENTITIES = 11;
        private const int SSH2_AGENT_IDENTITIES_ANSWER = 12;
        private const int SSH2_AGENTC_SIGN_REQUEST = 13;
        private const int SSH2_AGENT_SIGN_RESPONSE = 14;
        private const int SSH2_AGENTC_ADD_IDENTITY = 17;
        private const int SSH2_AGENTC_REMOVE_IDENTITY = 18;
        private const int SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
        private const int SSH2_AGENT_FAILURE = 30;

        bool _init = true;

        private Buffer rbuf = null;
        private Buffer wbuf = null;
        private Packet packet = null;
        private Buffer mbuf = null;

        internal ChannelAgentForwarding()
            : base()
        {


            setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
            setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
            setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);

            type = "auth-agent@openssh.com".getBytes();
            rbuf = new Buffer();
            rbuf.reset();
            //wbuf=new Buffer(rmpsize);
            //packet=new Packet(wbuf);
            mbuf = new Buffer();
            connected = true;
        }

        public override void run()
        {
            try
            {
                sendOpenConfirmation();
            }
            catch (Exception e)
            {
                close = true;
                disconnect();
            }
        }

        void write(byte[] foo, int s, int l)
        {

            if (packet == null)
            {
                wbuf = new Buffer(rmpsize);
                packet = new Packet(wbuf);
            }

            rbuf.shift();
            if (rbuf.buffer.Length < rbuf.index + l)
            {
                byte[] newbuf = new byte[rbuf.s + l];
                Array.Copy(rbuf.buffer, 0, newbuf, 0, rbuf.buffer.Length);
                rbuf.buffer = newbuf;
            }

            rbuf.putByte(foo, s, l);

            int mlen = rbuf.getInt();
            if (mlen > rbuf.getLength())
            {
                rbuf.s -= 4;
                return;
            }

            int typ = rbuf.getByte();

            Session _session = null;
            try
            {
                _session = getSession();
            }
            catch (JSchException e)
            {
                throw new IOException(e.ToString());
            }

            List<Identity> identities = _session.jsch.identities;
            UserInfo userinfo = _session.getUserInfo();

            if (typ == SSH2_AGENTC_REQUEST_IDENTITIES)
            {
                mbuf.reset();
                mbuf.putByte((byte)SSH2_AGENT_IDENTITIES_ANSWER);
                lock (identities)
                {
                    int count = 0;
                    for (int i = 0; i < identities.Count; i++)
                    {
                        Identity identity = identities[i];
                        if (identity.getPublicKeyBlob() != null)
                            count++;
                    }
                    mbuf.putInt(count);
                    for (int i = 0; i < identities.Count; i++)
                    {
                        Identity identity = identities[i];
                        byte[] pubkeyblob = identity.getPublicKeyBlob();
                        if (pubkeyblob == null)
                            continue;
                        mbuf.putString(pubkeyblob);
                        mbuf.putString("".getBytes());
                    }
                }
                byte[] bar = new byte[mbuf.getLength()];
                mbuf.getByte(bar);

                send(bar);
            }
            else if (typ == SSH2_AGENTC_SIGN_REQUEST)
            {
                byte[] blob = rbuf.getString();
                byte[] data = rbuf.getString();
                int flags = rbuf.getInt();

                //      if((flags & 1)!=0){ //SSH_AGENT_OLD_SIGNATURE // old OpenSSH 2.0, 2.1
                //        datafellows = SSH_BUG_SIGBLOB;
                //      }

                Identity identity = null;
                lock (identities)
                {
                    for (int i = 0; i < identities.Count; i++)
                    {
                        Identity _identity = identities[i];
                        if (_identity.getPublicKeyBlob() == null)
                            continue;
                        if (!Util.array_equals(blob, _identity.getPublicKeyBlob()))
                        {
                            continue;
                        }
                        if (_identity.isEncrypted())
                        {
                            if (userinfo == null)
                                continue;
                            while (_identity.isEncrypted())
                            {
                                if (!userinfo.promptPassphrase("Passphrase for " + _identity.getName()))
                                {
                                    break;
                                }

                                string _passphrase = userinfo.getPassphrase();
                                if (_passphrase == null)
                                {
                                    break;
                                }

                                byte[] passphrase = Util.str2byte(_passphrase);
                                try
                                {
                                    if (_identity.setPassphrase(passphrase))
                                    {
                                        break;
                                    }
                                }
                                catch (JSchException e)
                                {
                                    break;
                                }
                            }
                        }

                        if (!_identity.isEncrypted())
                        {
                            identity = _identity;
                            break;
                        }
                    }
                }

                byte[] signature = null;

                if (identity != null)
                {
                    signature = identity.getSignature(data);
                }

                mbuf.reset();
                if (signature == null)
                {
                    mbuf.putByte((byte)SSH2_AGENT_FAILURE);
                }
                else
                {
                    mbuf.putByte((byte)SSH2_AGENT_SIGN_RESPONSE);
                    mbuf.putString(signature);
                }

                byte[] bar = new byte[mbuf.getLength()];
                mbuf.getByte(bar);

                send(bar);
            }
        }

        private void send(byte[] message)
        {
            packet.reset();
            wbuf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
            wbuf.putInt(recipient);
            wbuf.putInt(4 + message.Length);
            wbuf.putString(message);

            try
            {
                getSession().write(packet, this, 4 + message.Length);
            }
            catch (Exception e)
            {
            }
        }
    }
}
