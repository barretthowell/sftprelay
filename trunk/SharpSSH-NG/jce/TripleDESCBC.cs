using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    public class TripleDESCBC : Cipher
    {

        private CryptoStream cs;
        private MemoryStream ms;
        private TripleDES desm;
        private const int BlockSize = 24;
        private const int IVSize = 8;
        public override int getIVSize()
        {
            return IVSize;
        }

        public override int getBlockSize()
        {
            return BlockSize;
        }

        public override void init(int mode, byte[] key, byte[] iv)
        {
            if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) throw new ArgumentOutOfRangeException();
            ms = new PipedMemoryStream();
            desm = TripleDES.Create();
            desm.KeySize = BlockSize * 8;
            desm.Padding = PaddingMode.None;
            ICryptoTransform ict;
            if (mode == ENCRYPT_MODE)
            {
                ict = desm.CreateEncryptor(key, iv);
            }
            else
            {
                ict = desm.CreateDecryptor(key, iv);
            }

            cs = new CryptoStream(ms, ict, CryptoStreamMode.Write);
        }

        public override void update(byte[] input, int inputOffset, int len, byte[] output, int outputOffset)
        {
            cs.Write(input, inputOffset, len);
            ms.Read(output, outputOffset, len);
        }
    }
}
