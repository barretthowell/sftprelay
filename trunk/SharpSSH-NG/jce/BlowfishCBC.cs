using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    class BlowfishCBC : Cipher
    {
        public override int getIVSize()
        {
            throw new NotImplementedException();
        }

        public override int getBlockSize()
        {
            throw new NotImplementedException();
        }

        public override void init(int mode, byte[] key, byte[] iv)
        {
            throw new NotImplementedException();
        }

        public override void update(byte[] input, int inputOffset, int len, byte[] output, int outputOffset)
        {
            throw new NotImplementedException();
        }
    }
}
