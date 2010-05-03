using System;

namespace SharpSSH.NG
{
    public interface Identity
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
