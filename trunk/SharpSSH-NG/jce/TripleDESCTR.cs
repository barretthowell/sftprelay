using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    public class TripleDESCTR:Cipher
    {
        
        protected ulong[] counter;
        protected byte[] counterBytes;
        protected byte[] buffer;
        private CryptoStream cs;
        private MemoryStream ms;
        private TripleDES desm;
        private const int RealBlockSize = 8;
        private const int BlockSize = 24;
        private const int IVSize = 8;
        
        public TripleDESCTR()
        {
            this.counter = new ulong[BlockSize / 8];
            for (int i = 0; i < counter.Length; i++)
                counter[i] = 0;
            this.counterBytes = new byte[RealBlockSize];
            for (int i = 0; i < counterBytes.Length; i++)
                counterBytes[i] = 0;
            this.buffer = new byte[RealBlockSize];
        }
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
            desm = TripleDES.Create();
            //desm.BlockSize = blockSize*8;
            desm.KeySize = BlockSize * 8;
            desm.Key = key;
            desm.IV = iv;
            ms = new MemoryStream(BlockSize);
        }
        private void incCounter()
        {
            for (int i = counterBytes.Length-1; i >= 0; i--)
            {
                if (counterBytes[i] < 255)
                {
                    counterBytes[i]++;
                    break;
                }
                counterBytes[i] = 0;
            }
        }
        private void updateBlock(byte[] input, int inputOffset, int len, byte[] output, int outputOffset)
        {
            ms.Position = 0;
            cs = new CryptoStream(ms, desm.CreateEncryptor(), CryptoStreamMode.Write);
            cs.Write(counterBytes);
            ms.Position = 0;
            ms.Read(buffer, 0, RealBlockSize);
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
                updateBlock(input, inputOffset, (len > RealBlockSize) ? RealBlockSize : len, output, outputOffset);
                inputOffset += RealBlockSize;
                outputOffset += RealBlockSize;
                len -= RealBlockSize;
            }
        }
    }
}
