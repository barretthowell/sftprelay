using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Org.Mentalis.Security.Cryptography;

namespace SharpSSH.NG.jce
{
    public class DH : SharpSSH.NG.DH
    {
        internal byte[] p;
        internal byte[] g;
        internal byte[] e;  // my public key
        internal byte[] e_array;
        internal byte[] f;  // your public key
        internal byte[] K;  // shared secret key
        internal byte[] K_array;

        private DiffieHellman dh;
        public void init()
        {
        }
        public byte[] getE()
        {
            if (e_array == null)
            {

                dh = new DiffieHellmanManaged(p, g, 0);
                e_array = dh.CreateKeyExchange();
            }
            return e_array;
        }
        public byte[] getK()
        {
            if (K_array == null)
            {
                K_array = dh.DecryptKeyExchange(f);
            }
            return K_array;
        }
        public void setP(byte[] p) { this.p = p; }
        public void setG(byte[] g) { this.g = g; }
        public void setF(byte[] f) { this.f = f; }
    }
}
