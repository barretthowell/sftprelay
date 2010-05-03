using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpSSH.NG;
using SSC = System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    class HMACSHA196:MAC
    {
        private const string name = "hmac-sha1-96";
        private const int BSIZE = 12;
        private const int ORIGBSIZE = 20;
        private SSC.HMAC mac;
        private SSC.CryptoStream cs;

        public HMACSHA196()
        {
        }

        #region MAC Members

        public string getName()
        {
            return name;
        }

        public int getBlockSize()
        {
            return BSIZE;
        }

        public void init(byte[] key)
        {
            if (key.Length > ORIGBSIZE)
            {
                byte[] tmp = new byte[ORIGBSIZE];
                Array.Copy(key, 0, tmp, 0, ORIGBSIZE);
                key = tmp;
            }
            mac = new SSC.HMACMD5(key);
            cs = new SSC.CryptoStream(Stream.Null, mac, SSC.CryptoStreamMode.Write);
        }

        public void update(byte[] foo, int start, int len)
        {
            cs.Write(foo, start, len);
        }

        public void update(int foo)
        {
            cs.Write(JavaCompat.GetBytesBig(foo));
        }

        public void doFinal(byte[] buf, int offset)
        {
            cs.Close();
            Array.Copy(mac.Hash, 0, buf, offset, BSIZE);
            byte[] key = (byte[])mac.Key.Clone();
            mac.Clear();
            init(key);
        }

        #endregion
    }
}
