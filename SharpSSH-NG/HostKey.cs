using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class HostKey
    {
        private static readonly byte[] sshdss = "ssh-dss".getBytes();
        private static readonly byte[] sshrsa = "ssh-rsa".getBytes();

        protected const int GUESS = 0;
        public const int SSHDSS = 1;
        public const int SSHRSA = 2;
        const int UNKNOWN = 3;

        protected string host;
        protected int type;
        protected byte[] key;

        public HostKey(string host, byte[] key)
        {
            this(host, GUESS, key);
        }

        public HostKey(string host, int type, byte[] key)
        {
            this.host = host;
            if (type == GUESS)
            {
                if (key[8] == 'd') { this.type = SSHDSS; }
                else if (key[8] == 'r') { this.type = SSHRSA; }
                else { throw new JSchException("invalid key type"); }
            }
            else
            {
                this.type = type;
            }
            this.key = key;
        }

        public string getHost() { return host; }
        public string getType()
        {
            if (type == SSHDSS) { return new string(sshdss); }
            if (type == SSHRSA) { return new string(sshrsa); }
            return "UNKNOWN";
        }
        public string getKey()
        {
            return new string(Util.toBase64(key, 0, key.Length));
        }
        public string getFingerPrint(JSch jsch)
        {
            HASH hash = null;
            try
            {
                Class c = Class.forName(jsch.getConfig("md5"));
                hash = (HASH)(c.newInstance());
            }
            catch (Exception e) { System.err.println("getFingerPrint: " + e); }
            return Util.getFingerPrint(hash, key);
        }

        bool isMatched(string _host)
        {
            return isIncluded(_host);
        }

        private bool isIncluded(string _host)
        {
            int i = 0;
            string hosts = this.host;
            int hostslen = hosts.Length;
            int hostlen = _host.Length;
            int j;
            while (i < hostslen)
            {
                j = hosts.IndexOf(',', i);
                if (j == -1)
                {
                    if (hostlen != hostslen - i) return false;
                    return hosts.regionMatches(true, i, _host, 0, hostlen);
                }
                if (hostlen == (j - i))
                {
                    if (hosts.regionMatches(true, i, _host, 0, hostlen)) return true;
                }
                i = j + 1;
            }
            return false;
        }
    }
}
