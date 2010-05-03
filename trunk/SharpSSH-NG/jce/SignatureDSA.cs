using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class SignatureDSA: SharpSSH.NG.SignatureDSA
    {
        #region SignatureDSA Members

        public void init()
        {
            throw new NotImplementedException();
        }

        public void setPubKey(byte[] y, byte[] p, byte[] q, byte[] g)
        {
            throw new NotImplementedException();
        }

        public void setPrvKey(byte[] x, byte[] p, byte[] q, byte[] g)
        {
            throw new NotImplementedException();
        }

        public void update(byte[] H)
        {
            throw new NotImplementedException();
        }

        public bool verify(byte[] sig)
        {
            throw new NotImplementedException();
        }

        public byte[] sign()
        {
            throw new NotImplementedException();
        }

        #endregion
    }
}
