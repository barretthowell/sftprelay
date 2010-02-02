using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    abstract class SftpProgressMonitor
    {
        public const int PUT = 0;
        public const int GET = 1;
        public abstract void init(int op, string src, string dest, long max);
        public abstract bool count(long count);
        public abstract void end();
    }
}
