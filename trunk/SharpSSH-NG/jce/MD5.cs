using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpSSH.NG;
using SSC = System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    class MD5:HASH
    {
        private const int BSIZE = 16;
        private SSC.HashAlgorithm md;
        private SSC.CryptoStream sc;

        #region HASH Members

        public void init()
        {
            md = SSC.MD5.Create();
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
            return md.Hash;
        }

        #endregion
    }
}
