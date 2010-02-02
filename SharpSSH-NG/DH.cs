using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    interface DH
    {
        void init();
        void setP(byte[] p);
        void setG(byte[] g);
        byte[] getE();
        void setF(byte[] f);
        byte[] getK();
    }
}
