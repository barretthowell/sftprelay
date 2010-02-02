using System;

namespace SharpSSH.NG
{
    interface Identity
    {
        bool setPassphrase(byte[] passphrase);
        byte[] getPublicKeyBlob();
        byte[] getSignature(byte[] data);
        bool decrypt();
        string getAlgName();
        string getName();
        bool isEncrypted();
        void clear();
    }
}
