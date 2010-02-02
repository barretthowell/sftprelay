using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    interface Random
    {
        void fill(byte[] foo, int start, int len);
    }
}
