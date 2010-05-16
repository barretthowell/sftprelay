using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SharpSSH.NG;
using System.IO;
using System.Security.Cryptography;

namespace SharpSSH.NG.jce
{
    public class AESCTR:Cipher
    {
        protected int ivSize;
        protected int blockSize;
        protected ulong[] counter;
        protected byte[] counterBytes;
        protected byte[] buffer;
        private CryptoStream cs;
        private MemoryStream ms;
        private Aes aesm;
        
        public AESCTR(int blockSize, int ivSize)
        {
            this.ivSize = ivSize;
            this.blockSize = blockSize;
            this.counter = new ulong[blockSize / 8];
            for (int i = 0; i < counter.Length; i++)
                counter[i] = 0;
            this.counterBytes = new byte[blockSize];
            for (int i = 0; i < counterBytes.Length; i++)
                counterBytes[i] = 0;
            this.buffer = new byte[blockSize];
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
            for (int i = 0; i < counter.Length; i++)
                counter[i] = 0;
            for (int i = 0; i < counterBytes.Length; i++)
                counterBytes[i] = 0;
            aesm = AesManaged.Create();
            aesm.BlockSize = blockSize*8;
            //aesm.KeySize = blockSize*8;
            aesm.Key = key;
            aesm.IV = iv;
            ms = new MemoryStream(blockSize);
        }
        private void incCounter()
        {
        }
        private void updateBlock(byte[] input, int inputOffset, int len, byte[] output, int outputOffset)
        {
            ms.Position = 0;
            cs = new CryptoStream(ms, aesm.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(counterBytes);
            ms.Position = 0;
            ms.Read(buffer,0,blockSize);
            for (int i = 0; i < len; i++)
            {
                output[outputOffset + i] = (byte) (input[inputOffset + i] ^ buffer[i]);
            }
            incCounter();
        }

        public override void update(byte[] input, int inputOffset, int len, byte[] output, int outputOffset)
        {
            while (len > 0)
            {
                updateBlock(input, inputOffset, (len > blockSize) ? blockSize : len, output, outputOffset);
                inputOffset += blockSize;
                outputOffset += blockSize;
                len -= blockSize;
            }
        }
    }
}
