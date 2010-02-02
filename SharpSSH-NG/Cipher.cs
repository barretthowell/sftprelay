using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    abstract class Cipher
    {
        public const int ENCRYPT_MODE = 0;
        public const int DECRYPT_MODE = 1;
        public abstract int getIVSize();
        public abstract int getBlockSize();
        public abstract void init(int mode, byte[] key, byte[] iv);
        public abstract void update(byte[] foo, int s1, int len, byte[] bar, int s2);
    }
}
