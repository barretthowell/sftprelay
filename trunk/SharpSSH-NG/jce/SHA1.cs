using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpSSH.NG;
using SSC = System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    class SHA1:HASH
    {
        private const int BSIZE = 20;
        private SSC.HashAlgorithm md;
        private SSC.CryptoStream sc;

        #region HASH Members

        public void init()
        {
            md = SSC.SHA1.Create();
            sc = new SSC.CryptoStream(Stream.Null, md, SSC.CryptoStreamMode.Write);
        }

        public int getBlockSize()
        {
            return BSIZE;
        }

        public void update(byte[] foo, int start, int len)
        {
            sc.Write(foo, start, len);
        }

        public byte[] digest()
        {
            sc.Close();
            byte[] res = md.Hash;
            init();
            return res;
        }

        #endregion
    }
}
