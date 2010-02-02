using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class CipherNone
    {
        private const int ivsize = 8;
        private const int bsize = 16;
        public int getIVSize() { return ivsize; }
        public int getBlockSize() { return bsize; }
        public void init(int mode, byte[] key, byte[] iv)
        {
        }
        public void update(byte[] foo, int s1, int len, byte[] bar, int s2)
        {
        }
    }
}
