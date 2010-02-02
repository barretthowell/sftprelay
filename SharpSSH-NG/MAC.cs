using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    interface MAC
    {
        string getName();
        int getBlockSize();
        void init(byte[] key);
        void update(byte[] foo, int start, int len);
        void update(int foo);
        void doFinal(byte[] buf, int offset);
    }
}
