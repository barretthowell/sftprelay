using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class IdentityFile
    {
        string identity;
        byte[] key;
        byte[] iv;
        private JSch jsch;
        private HASH hash;
        private byte[] encoded_data;

        private Cipher cipher;

        // DSA
        private byte[] P_array;
        private byte[] Q_array;
        private byte[] G_array;
        private byte[] pub_array;
        private byte[] prv_array;

        // RSA
        private byte[] n_array;   // modulus
        private byte[] e_array;   // public exponent
        private byte[] d_array;   // private exponent

        //  private string algname="ssh-dss";
        private string algname = "ssh-rsa";

        private const int ERROR = 0;
        private const int RSA = 1;
        private const int DSS = 2;
        private const int UNKNOWN = 3;

        private const int OPENSSH = 0;
        private const int FSECURE = 1;
        private const int PUTTY = 2;

        private int type = ERROR;
        private int keytype = OPENSSH;

        private byte[] publickeyblob = null;

        private bool encrypted = true;

        internal static IdentityFile newInstance(string prvfile, string pubfile, JSch jsch)
        {
            byte[] prvkey = null;
            byte[] pubkey = null;

            File file = null;
            FileStream fis = null;
            try
            {
                file = new File(prvfile);
                fis = new FileStream(prvfile);
                prvkey = new byte[(int)(file.length())];
                int len = 0;
                while (true)
                {
                    int i = fis.Read(prvkey, len, prvkey.Length - len);
                    if (i <= 0)
                        break;
                    len += i;
                }
                fis.Close();
            }
            catch (Exception e)
            {
                try { if (fis != null) fis.Close(); }
                catch (Exception ee) { }
                throw new JSchException(e.Message,e);
            }

            string _pubfile = pubfile;
            if (pubfile == null)
            {
                _pubfile = prvfile + ".pub";
            }

            try
            {
                file = new File(_pubfile);
                fis = new FileStream(_pubfile);
                pubkey = new byte[(int)(file.length())];
                int len = 0;
                while (true)
                {
                    int i = fis.Read(pubkey, len, pubkey.Length - len);
                    if (i <= 0)
                        break;
                    len += i;
                }
                fis.Close();
            }
            catch (Exception e)
            {
                try { if (fis != null) fis.Close(); }
                catch (Exception ee) { }
                if (pubfile != null)
                {
                    // The pubfile is explicitry given, but not accessible.
                    throw new JSchException(e.Message,e);
                }
            }
            return newInstance(prvfile, prvkey, pubkey, jsch);
        }

        internal static IdentityFile newInstance(string name, byte[] prvkey, byte[] pubkey, JSch jsch)
        {
            try
            {
                return new IdentityFile(name, prvkey, pubkey, jsch);
            }
            finally
            {
                Util.bzero(prvkey);
            }
        }

        private IdentityFile(string name, byte[] prvkey, byte[] pubkey, JSch jsch)
        {
            this.identity = name;
            this.jsch = jsch;
            try
            {
                Type c;
                c = Type.GetType((string)jsch.getConfig("3des-cbc"));
                cipher = (Cipher)(c.newInstance());
                key = new byte[cipher.getBlockSize()];   // 24
                iv = new byte[cipher.getIVSize()];       // 8
                c = Type.GetType((string)jsch.getConfig("md5"));
                hash = (HASH)(c.newInstance());
                hash.init();

                byte[] buf = prvkey;
                int len = buf.Length;

                int i = 0;
                while (i < len)
                {
                    if (buf[i] == 'B' && buf[i + 1] == 'E' && buf[i + 2] == 'G' && buf[i + 3] == 'I')
                    {
                        i += 6;
                        if (buf[i] == 'D' && buf[i + 1] == 'S' && buf[i + 2] == 'A') { type = DSS; }
                        else if (buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'A') { type = RSA; }
                        else if (buf[i] == 'S' && buf[i + 1] == 'S' && buf[i + 2] == 'H')
                        { // FSecure
                            type = UNKNOWN;
                            keytype = FSECURE;
                        }
                        else
                        {
                            //Console.Error.WriteLine("invalid format: "+identity);
                            throw new JSchException("invalid privatekey: " + identity);
                        }
                        i += 3;
                        continue;
                    }
                    if (buf[i] == 'A' && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-' &&
                       buf[i + 4] == '2' && buf[i + 5] == '5' && buf[i + 6] == '6' && buf[i + 7] == '-')
                    {
                        i += 8;
                        if (Session.checkCipher((string)jsch.getConfig("aes256-cbc")))
                        {
                            c = Type.GetType((string)jsch.getConfig("aes256-cbc"));
                            cipher = (Cipher)(c.newInstance());
                            key = new byte[cipher.getBlockSize()];
                            iv = new byte[cipher.getIVSize()];
                        }
                        else
                        {
                            throw new JSchException("privatekey: aes256-cbc is not available " + identity);
                        }
                        continue;
                    }
                    if (buf[i] == 'C' && buf[i + 1] == 'B' && buf[i + 2] == 'C' && buf[i + 3] == ',')
                    {
                        i += 4;
                        for (int ii = 0; ii < iv.Length; ii++)
                        {
                            iv[ii] = (byte)(((a2b(buf[i++]) << 4) & 0xf0) +
                              (a2b(buf[i++]) & 0xf));
                        }
                        continue;
                    }
                    if (buf[i] == 0x0d &&
                       i + 1 < buf.Length && buf[i + 1] == 0x0a)
                    {
                        i++;
                        continue;
                    }
                    if (buf[i] == 0x0a && i + 1 < buf.Length)
                    {
                        if (buf[i + 1] == 0x0a) { i += 2; break; }
                        if (buf[i + 1] == 0x0d &&
                           i + 2 < buf.Length && buf[i + 2] == 0x0a)
                        {
                            i += 3; break;
                        }
                        bool inheader = false;
                        for (int j = i + 1; j < buf.Length; j++)
                        {
                            if (buf[j] == 0x0a) break;
                            //if(buf[j]==0x0d) break;
                            if (buf[j] == ':') { inheader = true; break; }
                        }
                        if (!inheader)
                        {
                            i++;
                            encrypted = false;    // no passphrase
                            break;
                        }
                    }
                    i++;
                }

                if (type == ERROR)
                {
                    throw new JSchException("invalid privatekey: " + identity);
                }

                int start = i;
                while (i < len)
                {
                    if (buf[i] == 0x0a)
                    {
                        bool xd = (buf[i - 1] == 0x0d);
                        Array.Copy(buf, i + 1,
                             buf,
                             i - (xd ? 1 : 0),
                             len - i - 1 - (xd ? 1 : 0)
                             );
                        if (xd) len--;
                        len--;
                        continue;
                    }
                    if (buf[i] == '-') { break; }
                    i++;
                }
                encoded_data = Util.fromBase64(buf, start, i - start);

                if (encoded_data.Length > 4 &&            // FSecure
               encoded_data[0] == (byte)0x3f &&
               encoded_data[1] == (byte)0x6f &&
               encoded_data[2] == (byte)0xf9 &&
               encoded_data[3] == (byte)0xeb)
                {

                    Buffer _buf = new Buffer(encoded_data);
                    _buf.getInt();  // 0x3f6ff9be
                    _buf.getInt();
                    byte[] _type = _buf.getString();
                    //Console.Error.WriteLine("type: "+Encoding.UTF8.GetString(_type)); 
                    byte[] _cipher = _buf.getString();
                    string cipher = Encoding.UTF8.GetString(_cipher);
                    //Console.Error.WriteLine("cipher: "+cipher); 
                    if (cipher.Equals("3des-cbc"))
                    {
                        _buf.getInt();
                        byte[] foo = new byte[encoded_data.Length - _buf.getOffSet()];
                        _buf.getByte(foo);
                        encoded_data = foo;
                        encrypted = true;
                        throw new JSchException("unknown privatekey format: " + identity);
                    }
                    else if (cipher.Equals("none"))
                    {
                        _buf.getInt();
                        //_buf.getInt();

                        encrypted = false;

                        byte[] foo = new byte[encoded_data.Length - _buf.getOffSet()];
                        _buf.getByte(foo);
                        encoded_data = foo;
                    }

                }

                if (pubkey == null)
                {
                    return;
                }

                buf = pubkey;
                len = buf.Length;

                if (buf.Length > 4 &&             // FSecure's public key
               buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] == '-')
                {
                    i = 0;
                    do { i++; } while (len > i && buf[i] != 0x0a);
                    if (len <= i) return;
                    while (i < len)
                    {
                        if (buf[i] == 0x0a)
                        {
                            bool inheader = false;
                            for (int j = i + 1; j < len; j++)
                            {
                                if (buf[j] == 0x0a) break;
                                if (buf[j] == ':') { inheader = true; break; }
                            }
                            if (!inheader)
                            {
                                i++;
                                break;
                            }
                        }
                        i++;
                    }
                    if (len <= i) return;

                    start = i;
                    while (i < len)
                    {
                        if (buf[i] == 0x0a)
                        {
                            Array.Copy(buf, i + 1, buf, i, len - i - 1);
                            len--;
                            continue;
                        }
                        if (buf[i] == '-') { break; }
                        i++;
                    }
                    publickeyblob = Util.fromBase64(buf, start, i - start);

                    if (type == UNKNOWN && publickeyblob.Length > 8)
                    {
                        if (publickeyblob[8] == 'd')
                        {
                            type = DSS;
                        }
                        else if (publickeyblob[8] == 'r')
                        {
                            type = RSA;
                        }
                    }
                }
                else
                {
                    if (buf[0] != 's' || buf[1] != 's' || buf[2] != 'h' || buf[3] != '-') return;
                    i = 0;
                    while (i < len) { if (buf[i] == ' ')break; i++; } i++;
                    if (i >= len) return;
                    start = i;
                    while (i < len) { if (buf[i] == ' ' || buf[i] == '\n')break; i++; }
                    publickeyblob = Util.fromBase64(buf, start, i - start);
                    if (publickeyblob.Length < 4 + 7)
                    {  // It must start with "ssh-XXX".
                        if (JSch.getLogger().isEnabled(Logger.WARN))
                        {
                            JSch.getLogger().log(Logger.WARN,
                                                 "failed to parse the public key");
                        }
                        publickeyblob = null;
                    }
                }
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine("IdentityFile: "+e);
                if (e is JSchException) throw (JSchException)e;
                throw new JSchException(e.Message,e);
            }
        }

        public string getAlgName()
        {
            if (type == RSA) return "ssh-rsa";
            return "ssh-dss";
        }

        public bool setPassphrase(byte[] _passphrase)
        {
            /*
              hash is MD5
              h(0) <- hash(passphrase, iv);
              h(n) <- hash(h(n-1), passphrase, iv);
              key <- (h(0),...,h(n))[0,..,key.Length];
            */
            try
            {
                if (encrypted)
                {
                    if (_passphrase == null) return false;
                    byte[] passphrase = _passphrase;
                    int hsize = hash.getBlockSize();
                    byte[] hn = new byte[key.Length / hsize * hsize +
                               (key.Length % hsize == 0 ? 0 : hsize)];
                    byte[] tmp = null;
                    if (keytype == OPENSSH)
                    {
                        for (int index = 0; index + hsize <= hn.Length; )
                        {
                            if (tmp != null) { hash.update(tmp, 0, tmp.Length); }
                            hash.update(passphrase, 0, passphrase.Length);
                            hash.update(iv, 0, iv.Length > 8 ? 8 : iv.Length);
                            tmp = hash.digest();
                            Array.Copy(tmp, 0, hn, index, tmp.Length);
                            index += tmp.Length;
                        }
                        Array.Copy(hn, 0, key, 0, key.Length);
                    }
                    else if (keytype == FSECURE)
                    {
                        for (int index = 0; index + hsize <= hn.Length; )
                        {
                            if (tmp != null) { hash.update(tmp, 0, tmp.Length); }
                            hash.update(passphrase, 0, passphrase.Length);
                            tmp = hash.digest();
                            Array.Copy(tmp, 0, hn, index, tmp.Length);
                            index += tmp.Length;
                        }
                        Array.Copy(hn, 0, key, 0, key.Length);
                    }
                    Util.bzero(passphrase);
                }
                if (decrypt())
                {
                    encrypted = false;
                    return true;
                }
                P_array = Q_array = G_array = pub_array = prv_array = null;
                return false;
            }
            catch (Exception e)
            {
                if (e is JSchException) throw (JSchException)e;
                throw new JSchException(e.Message,e);
            }
        }

        public byte[] getPublicKeyBlob()
        {
            if (publickeyblob != null) return publickeyblob;
            if (type == RSA) return getPublicKeyBlob_rsa();
            return getPublicKeyBlob_dss();
        }

        byte[] getPublicKeyBlob_rsa()
        {
            if (e_array == null) return null;
            Buffer buf = new Buffer("ssh-rsa".Length + 4 +
                       e_array.Length + 4 +
                       n_array.Length + 4);
            buf.putString("ssh-rsa".getBytes());
            buf.putString(e_array);
            buf.putString(n_array);
            return buf.buffer;
        }

        byte[] getPublicKeyBlob_dss()
        {
            if (P_array == null) return null;
            Buffer buf = new Buffer("ssh-dss".Length + 4 +
                       P_array.Length + 4 +
                       Q_array.Length + 4 +
                       G_array.Length + 4 +
                       pub_array.Length + 4);
            buf.putString("ssh-dss".getBytes());
            buf.putString(P_array);
            buf.putString(Q_array);
            buf.putString(G_array);
            buf.putString(pub_array);
            return buf.buffer;
        }

        public byte[] getSignature(byte[] data)
        {
            if (type == RSA) return getSignature_rsa(data);
            return getSignature_dss(data);
        }

        byte[] getSignature_rsa(byte[] data)
        {
            try
            {
                Type c = Type.GetType((string)jsch.getConfig("signature.rsa"));
                SignatureRSA rsa = (SignatureRSA)(c.newInstance());

                rsa.init();
                rsa.setPrvKey(d_array, n_array);

                rsa.update(data);
                byte[] sig = rsa.sign();
                Buffer buf = new Buffer("ssh-rsa".Length + 4 +
                          sig.Length + 4);
                buf.putString("ssh-rsa".getBytes());
                buf.putString(sig);
                return buf.buffer;
            }
            catch (Exception e)
            {
            }
            return null;
        }

        byte[] getSignature_dss(byte[] data)
        {
            /*
                byte[] foo;
                int i;
                System.err.print("P ");
                foo=P_array;
                for(i=0;  i<foo.Length; i++){
                  System.err.print(Integer.toHexString(foo[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                System.err.print("Q ");
                foo=Q_array;
                for(i=0;  i<foo.Length; i++){
                  System.err.print(Integer.toHexString(foo[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                System.err.print("G ");
                foo=G_array;
                for(i=0;  i<foo.Length; i++){
                  System.err.print(Integer.toHexString(foo[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
            */

            try
            {
                Type c = Type.GetType((string)jsch.getConfig("signature.dss"));
                SignatureDSA dsa = (SignatureDSA)(c.newInstance());
                dsa.init();
                dsa.setPrvKey(prv_array, P_array, Q_array, G_array);

                dsa.update(data);
                byte[] sig = dsa.sign();
                Buffer buf = new Buffer("ssh-dss".Length + 4 +
                          sig.Length + 4);
                buf.putString("ssh-dss".getBytes());
                buf.putString(sig);
                return buf.buffer;
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine("e "+e);
            }
            return null;
        }

        public bool decrypt()
        {
            if (type == RSA) return decrypt_rsa();
            return decrypt_dss();
        }

        bool decrypt_rsa()
        {
            byte[] p_array;
            byte[] q_array;
            byte[] dmp1_array;
            byte[] dmq1_array;
            byte[] iqmp_array;

            try
            {
                byte[] plain;
                if (encrypted)
                {
                    if (keytype == OPENSSH)
                    {
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        plain = new byte[encoded_data.Length];
                        cipher.update(encoded_data, 0, encoded_data.Length, plain, 0);
                    }
                    else if (keytype == FSECURE)
                    {
                        for (int i = 0; i < iv.Length; i++) iv[i] = 0;
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        plain = new byte[encoded_data.Length];
                        cipher.update(encoded_data, 0, encoded_data.Length, plain, 0);
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    if (n_array != null) return true;
                    plain = encoded_data;
                }

                if (keytype == FSECURE)
                {              // FSecure   
                    Buffer buf = new Buffer(plain);
                    int foo = buf.getInt();
                    if (plain.Length != foo + 4)
                    {
                        return false;
                    }
                    e_array = buf.getMPIntBits();
                    d_array = buf.getMPIntBits();
                    n_array = buf.getMPIntBits();
                    byte[] u_array = buf.getMPIntBits();
                    p_array = buf.getMPIntBits();
                    q_array = buf.getMPIntBits();
                    return true;
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

                //Console.Error.WriteLine("int: len="+length);
                //System.err.print(Integer.toHexString(plain[index-1]&0xff)+":");
                //Console.Error.WriteLine("");

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                n_array = new byte[length];
                Array.Copy(plain, index, n_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: N len="+length);
                for(int i=0; i<n_array.Length; i++){
                System.err.print(Integer.toHexString(n_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                e_array = new byte[length];
                Array.Copy(plain, index, e_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: E len="+length);
                for(int i=0; i<e_array.Length; i++){
                System.err.print(Integer.toHexString(e_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                d_array = new byte[length];
                Array.Copy(plain, index, d_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: D len="+length);
                for(int i=0; i<d_array.Length; i++){
                System.err.print(Integer.toHexString(d_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */

                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                p_array = new byte[length];
                Array.Copy(plain, index, p_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: P len="+length);
                for(int i=0; i<p_array.Length; i++){
                System.err.print(Integer.toHexString(p_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                q_array = new byte[length];
                Array.Copy(plain, index, q_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: q len="+length);
                for(int i=0; i<q_array.Length; i++){
                System.err.print(Integer.toHexString(q_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                dmp1_array = new byte[length];
                Array.Copy(plain, index, dmp1_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: dmp1 len="+length);
                for(int i=0; i<dmp1_array.Length; i++){
                System.err.print(Integer.toHexString(dmp1_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                dmq1_array = new byte[length];
                Array.Copy(plain, index, dmq1_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: dmq1 len="+length);
                for(int i=0; i<dmq1_array.Length; i++){
                System.err.print(Integer.toHexString(dmq1_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
                index++;
                length = plain[index++] & 0xff;
                if ((length & 0x80) != 0)
                {
                    int foo = length & 0x7f; length = 0;
                    while (foo-- > 0) { length = (length << 8) + (plain[index++] & 0xff); }
                }
                iqmp_array = new byte[length];
                Array.Copy(plain, index, iqmp_array, 0, length);
                index += length;
                /*
                Console.Error.WriteLine("int: iqmp len="+length);
                for(int i=0; i<iqmp_array.Length; i++){
                System.err.print(Integer.toHexString(iqmp_array[i]&0xff)+":");
                }
                Console.Error.WriteLine("");
                */
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
                return false;
            }
            return true;
        }

        bool decrypt_dss()
        {
            try
            {
                byte[] plain;
                if (encrypted)
                {
                    if (keytype == OPENSSH)
                    {
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        plain = new byte[encoded_data.Length];
                        cipher.update(encoded_data, 0, encoded_data.Length, plain, 0);
                        /*
                        for(int i=0; i<plain.Length; i++){
                        System.err.print(Integer.toHexString(plain[i]&0xff)+":");
                        }
                        Console.Error.WriteLine("");
                        */
                    }
                    else if (keytype == FSECURE)
                    {
                        for (int i = 0; i < iv.Length; i++) iv[i] = 0;
                        cipher.init(Cipher.DECRYPT_MODE, key, iv);
                        plain = new byte[encoded_data.Length];
                        cipher.update(encoded_data, 0, encoded_data.Length, plain, 0);
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    if (P_array != null) return true;
                    plain = encoded_data;
                }

                if (keytype == FSECURE)
                {              // FSecure   
                    Buffer buf = new Buffer(plain);
                    int foo = buf.getInt();
                    if (plain.Length != foo + 4)
                    {
                        return false;
                    }
                    P_array = buf.getMPIntBits();
                    G_array = buf.getMPIntBits();
                    Q_array = buf.getMPIntBits();
                    pub_array = buf.getMPIntBits();
                    prv_array = buf.getMPIntBits();
                    return true;
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
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
                //e.printStackTrace();
                return false;
            }
            return true;
        }

        public bool isEncrypted()
        {
            return encrypted;
        }

        public string getName()
        {
            return identity;
        }

        private byte a2b(byte c)
        {
            if ('0' <= c && c <= '9') return (byte)(c - '0');
            if ('a' <= c && c <= 'z') return (byte)(c - 'a' + 10);
            return (byte)(c - 'A' + 10);
        }

        public bool equals(Object o)
        {
            if (!(o is IdentityFile)) return base.Equals(o);
            IdentityFile foo = (IdentityFile)o;
            return getName().Equals(foo.getName());
        }

        public void clear()
        {
            Util.bzero(encoded_data);
            Util.bzero(prv_array);
            Util.bzero(d_array);
            Util.bzero(key);
            Util.bzero(iv);
        }

        public void finalize()
        {
            clear();
        }
    }
}
