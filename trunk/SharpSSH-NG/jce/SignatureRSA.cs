using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SSC = System.Security.Cryptography;
using System.IO;

namespace SharpSSH.NG.jce
{
    public class SignatureRSA : SharpSSH.NG.SignatureRSA
    {
        SSC.SHA1 md;
        SSC.CryptoStream sc;
        SSC.RSAParameters RSAparams;

        public SignatureRSA()
        {
            md = SSC.SHA1.Create();
            sc = new SSC.CryptoStream(Stream.Null, md, SSC.CryptoStreamMode.Write);
            RSAparams = new SSC.RSAParameters();
        }
        #region SignatureRSA Members

        public void init()
        {
            //throw new NotImplementedException();
        }

        public void setPubKey(byte[] e, byte[] n)
        {
            RSAparams.Modulus = n;
            RSAparams.Exponent = e;
        }

        public void setPrvKey(byte[] d, byte[] n)
        {
            RSAparams.D = d;
            RSAparams.Modulus = n;
        }

        public void update(byte[] H)
        {
            sc.Write(H);
        }

        public bool verify(byte[] sig)
        {
            long i = 0;
            long j = 0;
            byte[] tmp;

            //Util.Dump("c:\\sig.bin", sig);

            if (sig[0] == 0 && sig[1] == 0 && sig[2] == 0)
            {
                long i1 = (sig[i++] << 24) & 0xff000000;
                long i2 = (sig[i++] << 16) & 0x00ff0000;
                long i3 = (sig[i++] << 8) & 0x0000ff00;
                long i4 = (sig[i++]) & 0x000000ff;
                j = i1 | i2 | i3 | i4;

                i += j;

                i1 = (sig[i++] << 24) & 0xff000000;
                i2 = (sig[i++] << 16) & 0x00ff0000;
                i3 = (sig[i++] << 8) & 0x0000ff00;
                i4 = (sig[i++]) & 0x000000ff;
                j = i1 | i2 | i3 | i4;

                tmp = new byte[j];
                Array.Copy(sig, i, tmp, 0, j); sig = tmp;
            }
            SSC.RSA rsa = SSC.RSA.Create();
            rsa.ImportParameters(RSAparams);
            SSC.RSAPKCS1SignatureDeformatter verifier = new SSC.RSAPKCS1SignatureDeformatter(rsa);
            verifier.SetHashAlgorithm("SHA1");
            sc.Close();
            return verifier.VerifySignature(md.Hash, sig);
        }

        public byte[] sign()
        {
            SSC.RSA rsa = SSC.RSA.Create();
            rsa.ImportParameters(RSAparams);
            SSC.RSAPKCS1SignatureFormatter signer = new SSC.RSAPKCS1SignatureFormatter(rsa);
            signer.SetHashAlgorithm("SHA1");
            sc.Close();
            return signer.CreateSignature(md.Hash);
        }

        #endregion
    }
}
