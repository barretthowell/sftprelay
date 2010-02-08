using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.CompilerServices;

namespace SharpSSH.NG
{
    class KnownHosts : HostKeyRepository
    {
        private const string _known_hosts = "known_hosts";

        /*
        const int SSHDSS=0;
        const int SSHRSA=1;
        const int UNKNOWN=2;
        */

        private JSch jsch = null;
        private string known_hosts = null;
        private List<HostKey> pool = null;

        private MAC hmacsha1 = null;

        internal KnownHosts(JSch jsch) :
            base()
        {
            this.jsch = jsch;
            pool = new List<HostKey>();
        }

        internal void setKnownHosts(string foo)
        {
            try
            {
                known_hosts = foo;
                FileStream fis = new FileStream(foo,FileMode.Open);
                setKnownHosts(fis);
            }
            catch (FileNotFoundException )
            {
            }
        }
        internal void setKnownHosts(Stream foo)
        {
            pool.Clear();
            StringBuilder sb = new StringBuilder();
            byte i;
            int j;
            bool error = false;
            try
            {
                Stream fis = foo;
                string host;
                string key = null;
                int type;
                byte[] buf = new byte[1024];
                int bufl = 0;

                while (true)
                {
                loop:
                    bufl = 0;
                    while (true)
                    {
                        j = fis.Read();
                        if (j == -1)
                        {
                            if (bufl == 0) { goto outloop; }
                            else { break; }
                        }
                        if (j == 0x0d) { continue; }
                        if (j == 0x0a) { break; }
                        if (buf.Length <= bufl)
                        {
                            if (bufl > 1024 * 10) break;   // too long...
                            byte[] newbuf = new byte[buf.Length * 2];
                            Array.Copy(buf, 0, newbuf, 0, buf.Length);
                            buf = newbuf;
                        }
                        buf[bufl++] = (byte)j;
                    }

                    j = 0;
                    while (j < bufl)
                    {
                        i = buf[j];
                        if (i == ' ' || i == '\t') { j++; continue; }
                        if (i == '#')
                        {
                            addInvalidLine(Encoding.UTF8.GetString(buf, 0, bufl));
                            goto loop;
                        }
                        break;
                    }
                    if (j >= bufl)
                    {
                        addInvalidLine(Encoding.UTF8.GetString(buf, 0, bufl));
                        goto loop;
                    }

                    sb.Length=0;
                    while (j < bufl)
                    {
                        i = buf[j++];
                        if (i == 0x20 || i == '\t') { break; }
                        sb.Append((char)i);
                    }
                    host = sb.ToString();
                    if (j >= bufl || host.Length == 0)
                    {
                        addInvalidLine(Encoding.UTF8.GetString(buf, 0, bufl));
                        goto loop;
                    }

                    sb.Length=0;
                    type = -1;
                    while (j < bufl)
                    {
                        i = buf[j++];
                        if (i == 0x20 || i == '\t') { break; }
                        sb.Append((char)i);
                    }
                    if (sb.ToString().Equals("ssh-dss")) { type = HostKey.SSHDSS; }
                    else if (sb.ToString().Equals("ssh-rsa")) { type = HostKey.SSHRSA; }
                    else { j = bufl; }
                    if (j >= bufl)
                    {
                        addInvalidLine(Encoding.UTF8.GetString(buf, 0, bufl));
                        goto loop;
                    }

                    sb.Length=0;
                    while (j < bufl)
                    {
                        i = buf[j++];
                        if (i == 0x0d) { continue; }
                        if (i == 0x0a) { break; }
                        sb.Append((char)i);
                    }
                    key = sb.ToString();
                    if (key.Length == 0)
                    {
                        addInvalidLine(Encoding.UTF8.GetString(buf, 0, bufl));
                        goto loop;
                    }

                    //Console.Error.WriteLine(host);
                    //Console.Error.WriteLine("|"+key+"|");

                    HostKey hk = null;
                    hk = new HashedHostKey(this, host, type,
                                           Util.fromBase64(key.getBytes(), 0,
                                                           key.Length));
                    pool.Add(hk);
                }
            outloop:
                fis.Close();
                if (error)
                {
                    throw new JSchException("KnownHosts: invalid format");
                }
            }
            catch (Exception e)
            {
                if (e is JSchException)
                    throw (JSchException)e;
                throw new JSchException(e.Message,e);
            }
        }
        private void addInvalidLine(string line)
        {
            HostKey hk = new HostKey(line, HostKey.UNKNOWN, null);
            pool.Add(hk);
        }
        string getKnownHostsFile() { return known_hosts; }
        public override string getKnownHostsRepositoryID() { return known_hosts; }

        public override int check(string host, byte[] key)
        {
            int result = NOT_INCLUDED;
            if (host == null)
            {
                return result;
            }

            int type = getType(key);
            HostKey hk;

            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    hk = pool[i];
                    if (hk.isMatched(host) && hk.type == type)
                    {
                        if (Util.array_equals(hk.key, key))
                        {
                            //Console.Error.WriteLine("find!!");
                            return OK;
                        }
                        else
                        {
                            result = CHANGED;
                        }
                    }
                }
            }
            //Console.Error.WriteLine("fail!!");
            return result;
        }
        public override void add(HostKey hostkey, UserInfo userinfo)
        {
            int type = hostkey.type;
            string host = hostkey.getHost();
            byte[] key = hostkey.key;

            HostKey hk = null;
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    hk = pool[i];
                    if (hk.isMatched(host) && hk.type == type)
                    {
                        /*
                              if(Util.array_equals(hk.key, key)){ return; }
                              if(hk.host.Equals(host)){
                                hk.key=key;
                                return;
                              }
                              else{
                                hk.host=deleteSubString(hk.host, host);
                                break;
                              }
                        */
                    }
                }
            }

            hk = hostkey;

            pool.Add(hk);

            string bar = getKnownHostsRepositoryID();
            if (bar != null)
            {
                bool foo = true;
                FileInfo goo = new FileInfo(bar);
                if (!goo.Exists)
                {
                    foo = false;
                    if (userinfo != null)
                    {
                        foo = userinfo.promptYesNo(bar + " does not exist.\n" +
                                                 "Are you sure you want to create it?"
                                                 );
                        DirectoryInfo dgoo = Directory.GetParent(bar);
                        if (foo && dgoo != null && !dgoo.Exists)
                        {
                            foo = userinfo.promptYesNo("The parent directory " + goo + " does not exist.\n" +
                                                     "Are you sure you want to create it?"
                                                     );
                            if (foo)
                            {
                                if (!dgoo.mkdirs())
                                {
                                    userinfo.showMessage(goo + " has not been created.");
                                    foo = false;
                                }
                                else
                                {
                                    userinfo.showMessage(goo + " has been succesfully created.\nPlease check its access permission.");
                                }
                            }
                        }
                        if (dgoo == null) foo = false;
                    }
                }
                if (foo)
                {
                    try
                    {
                        Sync(bar);
                    }
                    catch (Exception e) { Console.Error.WriteLine("sync known_hosts: " + e); }
                }
            }
        }

        public override HostKey[] getHostKey()
        {
            return getHostKey(null, null);
        }
        public override HostKey[] getHostKey(string host, string type)
        {
            lock (pool)
            {
                int count = 0;
                for (int i = 0; i < pool.Count; i++)
                {
                    HostKey hk = pool[i];
                    if (hk.type == HostKey.UNKNOWN) continue;
                    if (host == null ||
                       (hk.isMatched(host) &&
                        (type == null || hk.getType().Equals(type))))
                    {
                        count++;
                    }
                }
                if (count == 0) return null;
                HostKey[] foo = new HostKey[count];
                int j = 0;
                for (int i = 0; i < pool.Count; i++)
                {
                    HostKey hk = pool[i];
                    if (hk.type == HostKey.UNKNOWN) continue;
                    if (host == null ||
                       (hk.isMatched(host) &&
                        (type == null || hk.getType().Equals(type))))
                    {
                        foo[j++] = hk;
                    }
                }
                return foo;
            }
        }
        public override void remove(string host, string type)
        {
            remove(host, type, null);
        }
        public override void remove(string host, string type, byte[] key)
        {
            bool sync = false;
            lock (pool)
            {
                for (int i = 0; i < pool.Count; i++)
                {
                    HostKey hk = pool[i];
                    if (host == null ||
                   (hk.isMatched(host) &&
                    (type == null || (hk.getType().Equals(type) &&
                            (key == null || Util.array_equals(key, hk.key))))))
                    {
                        string hosts = hk.getHost();
                        if (hosts.Equals(host) ||
                           ((hk is HashedHostKey) &&
                            ((HashedHostKey)hk).isHashed()))
                        {
                            pool.Remove(hk);
                        }
                        else
                        {
                            hk.host = deleteSubString(hosts, host);
                        }
                        sync = true;
                    }
                }
            }
            if (sync)
            {
                try { Sync(); }
                catch /*(Exception e)*/ { };
            }
        }

        protected void Sync()
        {
            if (known_hosts != null)
                Sync(known_hosts);
        }
        [MethodImpl(MethodImplOptions.Synchronized)]
        protected void Sync(string foo)
        {
            if (foo == null) return;
            FileStream fos = new FileStream(foo,FileMode.Create);
            dump(fos);
            fos.Close();
        }

        private static readonly byte[] space = { (byte)0x20 };
        private static readonly byte[] cr = "\n".getBytes();
        void dump(Stream Out)
        {
            try
            {
                HostKey hk;
                lock (pool)
                {
                    for (int i = 0; i < pool.Count; i++)
                    {
                        hk = pool[i];
                        //hk.dump(Out);
                        string host = hk.getHost();
                        string type = hk.getType();
                        if (type.Equals("UNKNOWN"))
                        {
                            Out.Write(host.getBytes());
                            Out.Write(cr);
                            continue;
                        }
                        Out.Write(host.getBytes());
                        Out.Write(space);
                        Out.Write(type.getBytes());
                        Out.Write(space);
                        Out.Write(hk.getKey().getBytes());
                        Out.Write(cr);
                    }
                }
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
            }
        }
        private int getType(byte[] key)
        {
            if (key[8] == 'd') return HostKey.SSHDSS;
            if (key[8] == 'r') return HostKey.SSHRSA;
            return HostKey.UNKNOWN;
        }
        private string deleteSubString(string hosts, string host)
        {
            int i = 0;
            int hostlen = host.Length;
            int hostslen = hosts.Length;
            int j;
            while (i < hostslen)
            {
                j = hosts.IndexOf(',', i);
                if (j == -1) break;
                if (!host.Equals(hosts.Substring(i, j - i)))
                {
                    i = j + 1;
                    continue;
                }
                return hosts.Substring(0, i) + hosts.Substring(j + 1);
            }
            if (hosts.EndsWith(host) && hostslen - i == hostlen)
            {
                return hosts.Substring(0, (hostlen == hostslen) ? 0 : hostslen - hostlen - 1);
            }
            return hosts;
        }
        [MethodImpl(MethodImplOptions.Synchronized)]
        private MAC getHMACSHA1()
        {
            if (hmacsha1 == null)
            {
                try
                {
                    Type c = Type.GetType(JSch.getConfig("hmac-sha1"));
                    hmacsha1 = (MAC)(c.newInstance());
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine("hmacsha1: " + e);
                }
            }
            return hmacsha1;
        }

        internal HostKey createHashedHostKey(string host, byte[] key)
        {
            HashedHostKey hhk = new HashedHostKey(this,host, key);
            hhk.Hash();
            return hhk;
        }
        class HashedHostKey : HostKey
        {
            private const string HASH_MAGIC = "|1|";
            private const string HASH_DELIM = "|";

            private bool hashed = false;
            byte[] salt = null;
            byte[] hash = null;
            KnownHosts mykh;

            internal HashedHostKey(KnownHosts mykh, string host, byte[] key)
                :
                    this(mykh, host, GUESS, key)
            {
            }
            internal HashedHostKey(KnownHosts mykh, string host, int type, byte[] key) :
                base(host, type, key)
            {
                this.mykh = mykh;
                if (this.host.StartsWith(HASH_MAGIC) &&
                   this.host.Substring(HASH_MAGIC.Length).IndexOf(HASH_DELIM) > 0)
                {
                    string data = this.host.Substring(HASH_MAGIC.Length);
                    string _salt = data.Substring(0, data.IndexOf(HASH_DELIM));
                    string _hash = data.Substring(data.IndexOf(HASH_DELIM) + 1);
                    salt = Util.fromBase64(_salt.getBytes(), 0, _salt.Length);
                    hash = Util.fromBase64(_hash.getBytes(), 0, _hash.Length);
                    if (salt.Length != 20 ||  // block size of hmac-sha1
                       hash.Length != 20)
                    {
                        salt = null;
                        hash = null;
                        return;
                    }
                    hashed = true;
                }
            }

            internal override bool isMatched(string _host)
            {
                if (!hashed)
                {
                    return base.isMatched(_host);
                }
                MAC macsha1 = mykh.getHMACSHA1();
                try
                {
                    lock (macsha1)
                    {
                        macsha1.init(salt);
                        byte[] foo = _host.getBytes();
                        macsha1.update(foo, 0, foo.Length);
                        byte[] bar = new byte[macsha1.getBlockSize()];
                        macsha1.doFinal(bar, 0);
                        return Util.array_equals(hash, bar);
                    }
                }
                catch (Exception e)
                {
                    Console.Out.WriteLine(e);
                }
                return false;
            }

            internal bool isHashed()
            {
                return hashed;
            }

            internal void Hash()
            {
                if (hashed)
                    return;
                MAC macsha1 = mykh.getHMACSHA1();
                if (salt == null)
                {
                    Random random = Session.random;
                    lock (random)
                    {
                        salt = new byte[macsha1.getBlockSize()];
                        random.fill(salt, 0, salt.Length);
                    }
                }
                try
                {
                    lock (macsha1)
                    {
                        macsha1.init(salt);
                        byte[] foo = host.getBytes();
                        macsha1.update(foo, 0, foo.Length);
                        hash = new byte[macsha1.getBlockSize()];
                        macsha1.doFinal(hash, 0);
                    }
                }
                catch //(Exception e)
                {
                }
                host = HASH_MAGIC + Encoding.UTF8.GetString(Util.toBase64(salt, 0, salt.Length)) +
                  HASH_DELIM + Encoding.UTF8.GetString(Util.toBase64(hash, 0, hash.Length));
                hashed = true;
            }
        }
    }
}
