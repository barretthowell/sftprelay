using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpSSH.NG;
using System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    public class AESCBC : Cipher
    {
        protected int ivSize;
        protected int blockSize;
        private CryptoStream cs;
        private MemoryStream ms;
        private Aes aesm;

        public AESCBC(int blockSize, int ivSize)
        {
            this.ivSize = ivSize;
            this.blockSize = blockSize;
        }
        public override int getIVSize()
        {
            return ivSize;
        }

        public override int getBlockSize()
        {
            return blockSize;
        }

        public override void init(int mode, byte[] key, byte[] iv)
        {
            if (mode != ENCRYPT_MODE && mode != DECRYPT_MODE) throw new ArgumentOutOfRangeException();
            ms = new PipedMemoryStream();
            aesm = AesManaged.Create();
            aesm.BlockSize = blockSize * 8;
            aesm.Padding = PaddingMode.None;
            ICryptoTransform ict;
            if (mode == ENCRYPT_MODE)
            {
                ict = aesm.CreateEncryptor(key, iv);
            }
            else
            {
                ict = aesm.CreateDecryptor(key, iv);
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

