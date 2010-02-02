using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    interface HASH
    {
        void init();
        int getBlockSize();
        void update(byte[] foo, int start, int len);
        byte[] digest();
    }
}
