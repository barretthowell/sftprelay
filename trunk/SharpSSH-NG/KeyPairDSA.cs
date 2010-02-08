using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class KeyPairDSA : KeyPair
    {
        private byte[] P_array;
        private byte[] Q_array;
        private byte[] G_array;
        private byte[] pub_array;
        private byte[] prv_array;

        //private int key_size=0;
        private int key_size = 1024;

        public KeyPairDSA(JSch jsch) :
            base(jsch)
        {
        }

        protected override void generate(int key_size)
        {
            this.key_size = key_size;
            try
            {
                Type c = Type.GetType(JSch.getConfig("keypairgen.dsa"));
                KeyPairGenDSA keypairgen = (KeyPairGenDSA)(c.newInstance());
                keypairgen.init(key_size);
                P_array = keypairgen.getP();
                Q_array = keypairgen.getQ();
                G_array = keypairgen.getG();
                pub_array = keypairgen.getY();
                prv_array = keypairgen.getX();

                keypairgen = null;
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine("KeyPairDSA: "+e); 
                throw new JSchException(e.Message,e);
            }
        }

        private static readonly byte[] begin = "-----BEGIN DSA PRIVATE KEY-----".getBytes();
        private static readonly byte[] end = "-----END DSA PRIVATE KEY-----".getBytes();

        protected override byte[] getBegin() { return begin; }
        protected override byte[] getEnd() { return end; }

        protected override byte[] getPrivateKey()
        {
            int content =
              1 + countLength(1) + 1 +                           // INTEGER
              1 + countLength(P_array.Length) + P_array.Length + // INTEGER  P
              1 + countLength(Q_array.Length) + Q_array.Length + // INTEGER  Q
              1 + countLength(G_array.Length) + G_array.Length + // INTEGER  G
              1 + countLength(pub_array.Length) + pub_array.Length + // INTEGER  pub
              1 + countLength(prv_array.Length) + prv_array.Length;  // INTEGER  prv

            int total =
              1 + countLength(content) + content;   // SEQUENCE

            byte[] plain = new byte[total];
            int index = 0;
            index = writeSEQUENCE(plain, index, content);
            index = writeINTEGER(plain, index, new byte[1]);  // 0
            index = writeINTEGER(plain, index, P_array);
            index = writeINTEGER(plain, index, Q_array);
            index = writeINTEGER(plain, index, G_array);
            index = writeINTEGER(plain, index, pub_array);
            index = writeINTEGER(plain, index, prv_array);
            return plain;
        }

        protected override bool parse(byte[] plain)
        {
            try
            {

                if (vendor == VENDOR_FSECURE)
                {
                    if (plain[0] != 0x30)
                    {              // FSecure
                        Buffer buf = new Buffer(plain);
                        buf.getInt();
                        P_array = buf.getMPIntBits();
                        G_array = buf.getMPIntBits();
                        Q_array = buf.getMPIntBits();
                        pub_array = buf.getMPIntBits();
                        prv_array = buf.getMPIntBits();
                        return true;
                    }
                    return false;
                }

                int index = 0;
                int length = 0;

                if (plain[index] != 0x30) return false;
                index++; // SEQUENCE
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }

                if (plain[index] != 0x02) return false;
                index++; // INTEGER
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                index += length;

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                P_array = new byte[length];
                Array.Copy(plain, index, P_array, 0, length);
                index += length;

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                Q_array = new byte[length];
                Array.Copy(plain, index, Q_array, 0, length);
                index += length;

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                G_array = new byte[length];
                Array.Copy(plain, index, G_array, 0, length);
                index += length;

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                pub_array = new byte[length];
                Array.Copy(plain, index, pub_array, 0, length);
                index += length;

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                prv_array = new byte[length];
                Array.Copy(plain, index, prv_array, 0, length);
                index += length;
            }
            catch //(Exception e)
            {
                //Console.Error.WriteLine(e);
                //e.printStackTrace();
                return false;
            }
            return true;
        }

        public override byte[] getPublicKeyBlob()
        {
            byte[] foo = base.getPublicKeyBlob();
            if (foo != null) return foo;

            if (P_array == null) return null;

            Buffer buf = new Buffer(sshdss.Length + 4 +
                      P_array.Length + 4 +
                      Q_array.Length + 4 +
                      G_array.Length + 4 +
                      pub_array.Length + 4);
            buf.putString(sshdss);
            buf.putString(P_array);
            buf.putString(Q_array);
            buf.putString(G_array);
            buf.putString(pub_array);
            return buf.buffer;
        }

        private static readonly byte[] sshdss = "ssh-dss".getBytes();
        protected override byte[] getKeyTypeName() { return sshdss; }
        public override int getKeyType() { return DSA; }

        public override int getKeySize() { return key_size; }
        public override void dispose()
        {
            base.dispose();
            Util.bzero(prv_array);
        }
    }
}
