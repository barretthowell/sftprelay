using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    interface KeyPairGenRSA
    {
  void init(int key_size);
  byte[] getD();
  byte[] getE();
  byte[] getN();

  byte[] getC();
  byte[] getEP();
  byte[] getEQ();
  byte[] getP();
  byte[] getQ();
    }
}
