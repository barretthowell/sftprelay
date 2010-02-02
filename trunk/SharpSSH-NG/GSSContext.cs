using System;

namespace SharpSSH.NG
{
    interface GSSContext
    {
        void create(string user, string host);
        bool isEstablished();
        byte[] init(byte[] token, int s, int l);
        byte[] getMIC(byte[] message, int s, int l);
        void dispose();
    }
}
