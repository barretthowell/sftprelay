using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SharpSSH.NG
{
    class JSch
    {
        static Dictionary<string, string> config = new Dictionary<string, string>();
        static JSch()
        {
            //  config.Add("kex", "diffie-hellman-group-exchange-sha1");
            config["kex"] = "diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1";
            config.Add("server_host_key", "ssh-rsa,ssh-dss");
            //    config.Add("server_host_key", "ssh-dss,ssh-rsa");

            config.Add("cipher.s2c",
                       "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc");
            config.Add("cipher.c2s",
                       "aes128-ctr,aes128-cbc,3des-ctr,3des-cbc,blowfish-cbc,aes192-cbc,aes256-cbc");

            config.Add("mac.s2c", "hmac-md5,hmac-sha1,hmac-sha1-96,hmac-md5-96");
            config.Add("mac.c2s", "hmac-md5,hmac-sha1,hmac-sha1-96,hmac-md5-96");
            config.Add("compression.s2c", "none");
            // config.Add("compression.s2c", "zlib@openssh.com,zlib,none");
            config.Add("compression.c2s", "none");
            // config.Add("compression.c2s", "zlib@openssh.com,zlib,none");

            config.Add("lang.s2c", "");
            config.Add("lang.c2s", "");

            config.Add("compression_level", "6");

            config.Add("diffie-hellman-group-exchange-sha1",
                                        "SharpSSH.NG.DHGEX");
            config.Add("diffie-hellman-group1-sha1",
                                    "SharpSSH.NG.DHG1");

            config.Add("dh", "SharpSSH.NG.jce.DH");
            config.Add("3des-cbc", "SharpSSH.NG.jce.TripleDESCBC");
            config.Add("blowfish-cbc", "SharpSSH.NG.jce.BlowfishCBC");
            config.Add("hmac-sha1", "SharpSSH.NG.jce.HMACSHA1");
            config.Add("hmac-sha1-96", "SharpSSH.NG.jce.HMACSHA196");
            config.Add("hmac-md5", "SharpSSH.NG.jce.HMACMD5");
            config.Add("hmac-md5-96", "SharpSSH.NG.jce.HMACMD596");
            config.Add("sha-1", "SharpSSH.NG.jce.SHA1");
            config.Add("md5", "SharpSSH.NG.jce.MD5");
            config.Add("signature.dss", "SharpSSH.NG.jce.SignatureDSA");
            config.Add("signature.rsa", "SharpSSH.NG.jce.SignatureRSA");
            config.Add("keypairgen.dsa", "SharpSSH.NG.jce.KeyPairGenDSA");
            config.Add("keypairgen.rsa", "SharpSSH.NG.jce.KeyPairGenRSA");
            config.Add("random", "SharpSSH.NG.jce.Random");

            config.Add("none", "SharpSSH.NG.CipherNone");

            config.Add("aes128-cbc", "SharpSSH.NG.jce.AES128CBC");
            config.Add("aes192-cbc", "SharpSSH.NG.jce.AES192CBC");
            config.Add("aes256-cbc", "SharpSSH.NG.jce.AES256CBC");

            config.Add("aes128-ctr", "SharpSSH.NG.jce.AES128CTR");
            config.Add("aes192-ctr", "SharpSSH.NG.jce.AES192CTR");
            config.Add("aes256-ctr", "SharpSSH.NG.jce.AES256CTR");
            config.Add("3des-ctr", "SharpSSH.NG.jce.TripleDESCTR");
            config.Add("arcfour", "SharpSSH.NG.jce.ARCFOUR");
            config.Add("arcfour128", "SharpSSH.NG.jce.ARCFOUR128");
            config.Add("arcfour256", "SharpSSH.NG.jce.ARCFOUR256");

            config.Add("userauth.none", "SharpSSH.NG.UserAuthNone");
            config.Add("userauth.password", "SharpSSH.NG.UserAuthPassword");
            config.Add("userauth.keyboard-interactive", "SharpSSH.NG.UserAuthKeyboardInteractive");
            config.Add("userauth.publickey", "SharpSSH.NG.UserAuthPublicKey");
            config.Add("userauth.gssapi-with-mic", "SharpSSH.NG.UserAuthGSSAPIWithMIC");
            config.Add("gssapi-with-mic.krb5", "SharpSSH.NG.jgss.GSSContextKrb5");

            config.Add("zlib", "SharpSSH.NG.jcraft.Compression");
            config.Add("zlib@openssh.com", "SharpSSH.NG.jcraft.Compression");

            config.Add("StrictHostKeyChecking", "ask");
            config.Add("HashKnownHosts", "no");
            //config.Add("HashKnownHosts",  "yes");
            config.Add("PreferredAuthentications", "gssapi-with-mic,publickey,keyboard-interactive,password");

            config.Add("CheckCiphers", "aes256-ctr,aes192-ctr,aes128-ctr,aes256-cbc,aes192-cbc,aes128-cbc,3des-ctr,arcfour,arcfour128,arcfour256");
        }
        List<Session> pool = new List<Session>();
        internal List<Identity> identities = new List<Identity>();
        private HostKeyRepository known_hosts = null;
        private class DEVNULL : Logger
        {
            public override bool isEnabled(int level) { return false; }
            public override void log(int level, string message) { }
        }
        static Logger logger = new DEVNULL();

        public JSch()
        {

            try
            {
                if (Environment.OSVersion.Platform == PlatformID.MacOSX)
                {
                    config.Add("hmac-sha1", "SharpSSH.NG.jcraft.HMACSHA1");
                    config.Add("hmac-md5", "SharpSSH.NG.jcraft.HMACMD5");
                    config.Add("hmac-md5-96", "SharpSSH.NG.jcraft.HMACMD596");
                    config.Add("hmac-sha1-96", "SharpSSH.NG.jcraft.HMACSHA196");
                }
            }
            catch //(Exception e)
            {
            }

        }

        public Session getSession(string username, string host) { return getSession(username, host, 22); }
        public Session getSession(string username, string host, int port)
        {
            if (username == null)
            {
                throw new JSchException("username must not be null.");
            }
            if (host == null)
            {
                throw new JSchException("host must not be null.");
            }
            Session s = new Session(this);
            s.setUserName(username);
            s.setHost(host);
            s.setPort(port);
            //pool.Add(s);
            return s;
        }

        internal void addSession(Session session)
        {
            lock (pool)
            {
                pool.Add(session);
            }
        }

        internal bool removeSession(Session session)
        {
            lock (pool)
            {
                return pool.Remove(session);
            }
        }
        public void setHostKeyRepository(HostKeyRepository hkrepo)
        {
            known_hosts = hkrepo;
        }

        public void setKnownHosts(string filename)
        {
            if (known_hosts == null) known_hosts = new KnownHosts(this);
            if (known_hosts is KnownHosts)
            {
                lock (known_hosts)
                {
                    ((KnownHosts)known_hosts).setKnownHosts(filename);
                }
            }
        }

        public void setKnownHosts(Stream stream)
        {
            if (known_hosts == null) known_hosts = new KnownHosts(this);
            if (known_hosts is KnownHosts)
            {
                lock (known_hosts)
                {
                    ((KnownHosts)known_hosts).setKnownHosts(stream);
                }
            }
        }

        public HostKeyRepository getHostKeyRepository()
        {
            if (known_hosts == null) known_hosts = new KnownHosts(this);
            return known_hosts;
        }

        public void addIdentity(string prvkey)
        {
            addIdentity(prvkey, (byte[])null);
        }

        public void addIdentity(string prvkey, string passphrase)
        {
            byte[] _passphrase = null;
            if (passphrase != null)
            {
                _passphrase = Util.str2byte(passphrase);
            }
            addIdentity(prvkey, _passphrase);
            if (_passphrase != null)
                Util.bzero(_passphrase);
        }

        public void addIdentity(string prvkey, byte[] passphrase)
        {
            Identity identity = (Identity)IdentityFile.newInstance(prvkey, null, this);
            addIdentity(identity, passphrase);
        }
        public void addIdentity(string prvkey, string pubkey, byte[] passphrase)
        {
            Identity identity = (Identity)IdentityFile.newInstance(prvkey, pubkey, this);
            addIdentity(identity, passphrase);
        }

        public void addIdentity(string name, byte[] prvkey, byte[] pubkey, byte[] passphrase)
        {
            Identity identity = (Identity)IdentityFile.newInstance(name, prvkey, pubkey, this);
            addIdentity(identity, passphrase);
        }

        public void addIdentity(Identity identity, byte[] passphrase)
        {
            if (passphrase != null)
            {
                try
                {
                    byte[] goo = new byte[passphrase.Length];
                    Array.Copy(passphrase, 0, goo, 0, passphrase.Length);
                    passphrase = goo;
                    identity.setPassphrase(passphrase);
                }
                finally
                {
                    Util.bzero(passphrase);
                }
            }
            lock (identities)
            {
                if (!identities.Contains(identity))
                {
                    identities.Add(identity);
                }
            }
        }

        public void removeIdentity(string name)
        {
            lock (identities)
            {
                for (int i = 0; i < identities.Count; i++)
                {
                    Identity identity = identities[i];
                    if (!identity.getName().Equals(name))
                        continue;
                    identities.Remove(identity);
                    identity.clear();
                    break;
                }
            }
        }

        public List<string> getIdentityNames()
        {
            List<string> foo = new List<string>();
            lock (identities)
            {
                for (int i = 0; i < identities.Count; i++)
                {
                    Identity identity = (Identity)(identities[i]);
                    foo.Add(identity.getName());
                }
            }
            return foo;
        }

        public void removeAllIdentity()
        {
            lock (identities)
            {
                List<string> foo = getIdentityNames();
                for (int i = 0; i < foo.Count; i++)
                {
                    string name = foo[i];
                    removeIdentity(name);
                }
            }
        }

        public static string getConfig(string key)
        {
            lock (config)
            {
                return config[key];
            }
        }

        public static void setConfig(Dictionary<string,string> newconf)
        {
            lock (config)
            {
                foreach (KeyValuePair<string, string> kv in newconf)
                {
                    config[kv.Key] = kv.Value;
                }
            }
        }

        public static void setConfig(string key, string value)
        {
            config[key]= value;
        }

        public static void setLogger(Logger logger)
        {
            if (logger == null) JSch.logger = new DEVNULL();
            JSch.logger = logger;
        }
        internal static Logger getLogger()
        {
            return logger;
        }
    }
}
   