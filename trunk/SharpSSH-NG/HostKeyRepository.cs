using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    public abstract class HostKeyRepository
    {
        public const int OK = 0;
        public const int NOT_INCLUDED = 1;
        public const int CHANGED = 2;

        public abstract int check(string host, byte[] key);
        public abstract void add(HostKey hostkey, UserInfo ui);
        public abstract void remove(string host, string type);
        public abstract void remove(string host, string type, byte[] key);
        public abstract string getKnownHostsRepositoryID();
        public abstract HostKey[] getHostKey();
        public abstract HostKey[] getHostKey(string host, string type);
    }
}
