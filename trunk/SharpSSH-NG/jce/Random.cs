using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SNG = SharpSSH.NG;
using SSC = System.Security.Cryptography;

namespace SharpSSH.NG.jce
{
    class Random  : SNG.Random
    {
        private byte[] tmp = new byte[128];
        private SSC.RandomNumberGenerator rng;
        public Random()
        {
            rng = SSC.RandomNumberGenerator.Create();
        }
        #region Random Members

        public void fill(byte[] foo, int start, int len)
        {
            while (len > tmp.Length)
            {
                rng.GetBytes(tmp);
                Array.Copy(tmp, 0, foo, start, tmp.Length);
                len -= tmp.Length;
                start += tmp.Length;
            }
            rng.GetBytes(tmp);
            Array.Copy(tmp, 0, foo, start, len);
        }

        #endregion
    }
}
