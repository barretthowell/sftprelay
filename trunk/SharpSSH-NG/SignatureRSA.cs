using System;

namespace SharpSSH.NG
{
    interface SignatureRSA
    {
        void init();
        void setPubKey(byte[] e, byte[] n);
        void setPrvKey(byte[] d, byte[] n);
        void update(byte[] H);
        bool verify(byte[] sig);
        byte[] sign();
    }
}
