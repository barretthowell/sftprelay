using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    interface KeyPairGenDSA
    {
        void init(int key_size);
        byte[] getX();
        byte[] getY();
        byte[] getP();
        byte[] getQ();
        byte[] getG();
    }
}
