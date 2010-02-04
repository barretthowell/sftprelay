using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Runtime.CompilerServices;

namespace SharpSSH.NG
{
    abstract class KeyPair
    {
        public const int ERROR = 0;
        public const int DSA = 1;
        public const int RSA = 2;
        public const int UNKNOWN = 3;

        const int VENDOR_OPENSSH = 0;
        const int VENDOR_FSECURE = 1;
        int vendor = VENDOR_OPENSSH;

        private static readonly byte[] cr = "\n".getBytes();

        public static KeyPair genKeyPair(JSch jsch, int type)
        {
            return genKeyPair(jsch, type, 1024);
        }
        public static KeyPair genKeyPair(JSch jsch, int type, int key_size)
        {
            KeyPair kpair = null;
            if (type == DSA) { kpair = new KeyPairDSA(jsch); }
            else if (type == RSA) { kpair = new KeyPairRSA(jsch); }
            if (kpair != null)
            {
                kpair.generate(key_size);
            }
            return kpair;
        }

        protected abstract void generate(int key_size);

        protected abstract byte[] getBegin();
        protected abstract byte[] getEnd();
        public abstract int getKeySize();

        JSch jsch = null;
        private Cipher cipher;
        private HASH hash;
        private Random random;

        private byte[] passphrase;

        public KeyPair(JSch jsch)
        {
            this.jsch = jsch;
        }

        static byte[][] header ={"Proc-Type: 4,ENCRYPTED".getBytes(),
			  "DEK-Info: DES-EDE3-CBC,".getBytes()};

        protected abstract byte[] getPrivateKey();

        public void writePrivateKey(Stream Out)
        {
            byte[] plain = getPrivateKey();
            byte[][] _iv = new byte[1][];
            byte[] encoded = encrypt(plain, _iv);
            if (encoded != plain)
                Util.bzero(plain);
            byte[] iv = _iv[0];
            byte[] prv = Util.toBase64(encoded, 0, encoded.Length);

            try
            {
                Out.write(getBegin()); Out.write(cr);
                if (passphrase != null)
                {
                    Out.write(header[0]); Out.write(cr);
                    Out.write(header[1]);
                    for (int i = 0; i < iv.Length; i++)
                    {
                        Out.write(b2a((byte)((iv[i] >> 4) & 0x0f)));
                        Out.write(b2a((byte)(iv[i] & 0x0f)));
                    }
                    Out.write(cr);
                    Out.write(cr);
                }
                int i = 0;
                while (i < prv.Length)
                {
                    if (i + 64 < prv.Length)
                    {
                        Out.write(prv, i, 64);
                        Out.write(cr);
                        i += 64;
                        continue;
                    }
                    Out.write(prv, i, prv.Length - i);
                    Out.write(cr);
                    break;
                }
                Out.write(getEnd()); Out.write(cr);
                //Out.close();
            }
            catch (Exception e)
            {
            }
        }

        private static byte[] space = " ".getBytes();

        protected abstract byte[] getKeyTypeName();
        public abstract int getKeyType();

        public virtual byte[] getPublicKeyBlob() { return publickeyblob; }

        public void writePublicKey(Stream Out, string comment)
        {
            byte[] pubblob = getPublicKeyBlob();
            byte[] pub = Util.toBase64(pubblob, 0, pubblob.Length);
            try
            {
                Out.write(getKeyTypeName()); Out.write(space);
                Out.write(pub, 0, pub.Length); Out.write(space);
                Out.write(comment.getBytes());
                Out.write(cr);
            }
            catch (Exception e)
            {
            }
        }

        public void writePublicKey(string name, string comment)
        {
            FileStream fos = new FileStream(name);
            writePublicKey(fos, comment);
            fos.close();
        }

        public void writeSECSHPublicKey(Stream Out, string comment)
        {
            byte[] pubblob = getPublicKeyBlob();
            byte[] pub = Util.toBase64(pubblob, 0, pubblob.Length);
            try
            {
                Out.write("---- BEGIN SSH2 PUBLIC KEY ----".getBytes()); Out.write(cr);
                Out.write(("Comment: \"" + comment + "\"").getBytes()); Out.write(cr);
                int index = 0;
                while (index < pub.Length)
                {
                    int len = 70;
                    if ((pub.Length - index) < len) len = pub.Length - index;
                    Out.write(pub, index, len); Out.write(cr);
                    index += len;
                }
                Out.write("---- END SSH2 PUBLIC KEY ----".getBytes()); Out.write(cr);
            }
            catch (Exception e)
            {
            }
        }

        public void writeSECSHPublicKey(string name, string comment)
        {
            FileStream fos = new FileStream(name);
            writeSECSHPublicKey(fos, comment);
            fos.close();
        }


        public void writePrivateKey(string name)
        {
            FileOutputStream fos = new FileOutputStream(name);
            writePrivateKey(fos);
            fos.close();
        }

        public string getFingerPrint()
        {
            if (hash == null) hash = genHash();
            byte[] kblob = getPublicKeyBlob();
            if (kblob == null) return null;
            return getKeySize() + " " + Util.getFingerPrint(hash, kblob);
        }

        private byte[] encrypt(byte[] plain, byte[][] _iv)
        {
            if (passphrase == null) return plain;

            if (cipher == null) cipher = genCipher();
            byte[] iv = _iv[0] = new byte[cipher.getIVSize()];

            if (random == null) random = genRandom();
            random.fill(iv, 0, iv.Length);

            byte[] key = genKey(passphrase, iv);
            byte[] encoded = plain;

            // PKCS#5Padding
            {
                //int bsize=cipher.getBlockSize();
                int bsize = cipher.getIVSize();
                byte[] foo = new byte[(encoded.Length / bsize + 1) * bsize];
                Array.Copy(encoded, 0, foo, 0, encoded.Length);
                int padding = bsize - encoded.Length % bsize;
                for (int i = foo.Length - 1; (foo.Length - padding) <= i; i--)
                {
                    foo[i] = (byte)padding;
                }
                encoded = foo;
            }

            try
            {
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
                cipher.update(encoded, 0, encoded.Length, encoded, 0);
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
            }
            Util.bzero(key);
            return encoded;
        }

        protected abstract bool parse(byte[] data);

        private byte[] decrypt(byte[] data, byte[] passphrase, byte[] iv)
        {
            /*
            if(iv==null){  // FSecure
              iv=new byte[8];
              for(int i=0; i<iv.Length; i++)iv[i]=0;
            }
            */
            try
            {
                byte[] key = genKey(passphrase, iv);
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
                Util.bzero(key);
                byte[] plain = new byte[data.Length];
                cipher.update(data, 0, data.Length, plain, 0);
                return plain;
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
            }
            return null;
        }

        int writeSEQUENCE(byte[] buf, int index, int len)
        {
            buf[index++] = 0x30;
            index = writeLength(buf, index, len);
            return index;
        }
        int writeINTEGER(byte[] buf, int index, byte[] data)
        {
            buf[index++] = 0x02;
            index = writeLength(buf, index, data.Length);
            Array.Copy(data, 0, buf, index, data.Length);
            index += data.Length;
            return index;
        }

        int countLength(int len)
        {
            uint ulen = (uint)len;
            int i = 1;
            if (ulen <= 0x7f) return i;
            while (ulen > 0)
            {
                ulen >>= 8;
                i++;
            }
            return i;
        }

        int writeLength(byte[] data, int index, int len)
        {
            int i = countLength(len) - 1;
            if (i == 0)
            {
                data[index++] = (byte)len;
                return index;
            }
            data[index++] = (byte)(0x80 | i);
            int j = index + i;
            uint ulen = (uint)len;
            while (i > 0)
            {
                data[index + i - 1] = (byte)(ulen & 0xff);
                ulen >>= 8;
                i--;
            }
            return j;
        }

        private Random genRandom()
        {
            if (random == null)
            {
                try
                {
                    Type c = Type.GetType(jsch.getConfig("random"));
                    random = (Random)(c.newInstance());
                }
                catch (Exception e) { Console.Error.WriteLine("connect: random " + e); }
            }
            return random;
        }

        private HASH genHash()
        {
            try
            {
                Type c = Type.GetType(jsch.getConfig("md5"));
                hash = (HASH)(c.newInstance());
                hash.init();
            }
            catch (Exception e)
            {
            }
            return hash;
        }
        private Cipher genCipher()
        {
            try
            {
                Type c;
                c = Type.GetType(jsch.getConfig("3des-cbc"));
                cipher = (Cipher)(c.newInstance());
            }
            catch (Exception e)
            {
            }
            return cipher;
        }

        /*
          hash is MD5
          h(0) <- hash(passphrase, iv);
          h(n) <- hash(h(n-1), passphrase, iv);
          key <- (h(0),...,h(n))[0,..,key.Length];
        */
        [MethodImpl(MethodImplOptions.Synchronized)]
        byte[] genKey(byte[] passphrase, byte[] iv)
        {
            if (cipher == null) cipher = genCipher();
            if (hash == null) hash = genHash();

            byte[] key = new byte[cipher.getBlockSize()];
            int hsize = hash.getBlockSize();
            byte[] hn = new byte[key.Length / hsize * hsize +
                       (key.Length % hsize == 0 ? 0 : hsize)];
            try
            {
                byte[] tmp = null;
                if (vendor == VENDOR_OPENSSH)
                {
                    for (int index = 0; index + hsize <= hn.Length; )
                    {
                        if (tmp != null) { hash.update(tmp, 0, tmp.Length); }
                        hash.update(passphrase, 0, passphrase.Length);
                        hash.update(iv, 0, iv.Length);
                        tmp = hash.digest();
                        Array.Copy(tmp, 0, hn, index, tmp.Length);
                        index += tmp.Length;
                    }
                    Array.Copy(hn, 0, key, 0, key.Length);
                }
                else if (vendor == VENDOR_FSECURE)
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
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
            }
            return key;
        }

        public void setPassphrase(string passphrase)
        {
            if (passphrase == null || passphrase.Length == 0)
            {
                setPassphrase((byte[])null);
            }
            else
            {
                setPassphrase(Util.str2byte(passphrase));
            }
        }
        public void setPassphrase(byte[] passphrase)
        {
            if (passphrase != null && passphrase.Length == 0)
                passphrase = null;
            this.passphrase = passphrase;
        }

        private bool encrypted = false;
        private byte[] data = null;
        private byte[] iv = null;
        private byte[] publickeyblob = null;

        public bool isEncrypted() { return encrypted; }
        public bool decrypt(string _passphrase)
        {
            if (_passphrase == null || _passphrase.Length == 0)
            {
                return !encrypted;
            }
            return decrypt(Util.str2byte(_passphrase));
        }
        public bool decrypt(byte[] _passphrase)
        {
            if (!encrypted)
            {
                return true;
            }
            if (_passphrase == null)
            {
                return !encrypted;
            }
            byte[] bar = new byte[_passphrase.Length];
            Array.Copy(_passphrase, 0, bar, 0, bar.Length);
            _passphrase = bar;
            byte[] foo = decrypt(data, _passphrase, iv);
            Util.bzero(_passphrase);
            if (parse(foo))
            {
                encrypted = false;
            }
            return !encrypted;
        }

        public static KeyPair load(JSch jsch, string prvkey)
        {
            string pubkey = prvkey + ".pub";
            if (!new File(pubkey).exists())
            {
                pubkey = null;
            }
            return load(jsch, prvkey, pubkey);
        }
        public static KeyPair load(JSch jsch, string prvkey, string pubkey)
        {

            byte[] iv = new byte[8];       // 8
            bool encrypted = true;
            byte[] data = null;

            byte[] publickeyblob = null;

            int type = ERROR;
            int vendor = VENDOR_OPENSSH;

            try
            {
                //File file = new File(prvkey);

                FileStream fis = new FileStream(prvkey,FileMode.Open);
                byte[] buf = new byte[fis.Length];
                int len = 0;
                while (true)
                {
                    int i = fis.read(buf, len, buf.Length - len);
                    if (i <= 0)
                        break;
                    len += i;
                }
                fis.close();

                int i = 0;

                while (i < len)
                {
                    if (buf[i] == 'B' && buf[i + 1] == 'E' && buf[i + 2] == 'G' && buf[i + 3] == 'I')
                    {
                        i += 6;
                        if (buf[i] == 'D' && buf[i + 1] == 'S' && buf[i + 2] == 'A') { type = DSA; }
                        else if (buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'A') { type = RSA; }
                        else if (buf[i] == 'S' && buf[i + 1] == 'S' && buf[i + 2] == 'H')
                        { // FSecure
                            type = UNKNOWN;
                            vendor = VENDOR_FSECURE;
                        }
                        else
                        {
                            //Console.Error.WriteLine("invalid format: "+identity);
                            throw new JSchException("invalid privatekey: " + prvkey);
                        }
                        i += 3;
                        continue;
                    }
                    if (buf[i] == 'C' && buf[i + 1] == 'B' && buf[i + 2] == 'C' && buf[i + 3] == ',')
                    {
                        i += 4;
                        for (int ii = 0; ii < iv.Length; ii++)
                        {
                            iv[ii] = (byte)(((a2b(buf[i++]) << 4) & 0xf0) + (a2b(buf[i++]) & 0xf));
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
                    throw new JSchException("invalid privatekey: " + prvkey);
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
                data = Util.fromBase64(buf, start, i - start);

                if (data.Length > 4 &&            // FSecure
               data[0] == (byte)0x3f &&
               data[1] == (byte)0x6f &&
               data[2] == (byte)0xf9 &&
               data[3] == (byte)0xeb)
                {

                    Buffer _buf = new Buffer(data);
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
                        byte[] foo = new byte[data.Length - _buf.getOffSet()];
                        _buf.getByte(foo);
                        data = foo;
                        encrypted = true;
                        throw new JSchException("unknown privatekey format: " + prvkey);
                    }
                    else if (cipher.Equals("none"))
                    {
                        _buf.getInt();
                        _buf.getInt();

                        encrypted = false;

                        byte[] foo = new byte[data.Length - _buf.getOffSet()];
                        _buf.getByte(foo);
                        data = foo;
                    }
                }

                if (pubkey != null)
                {
                    try
                    {
                        fis = new FileStream(pubkey);
                        buf = new byte[fis.Length];
                        len = 0;
                        while (true)
                        {
                            i = fis.read(buf, len, buf.Length - len);
                            if (i <= 0)
                                break;
                            len += i;
                        }
                        fis.close();

                        if (buf.Length > 4 &&             // FSecure's public key
                           buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] == '-')
                        {

                            bool valid = true;
                            i = 0;
                            do { i++; } while (buf.Length > i && buf[i] != 0x0a);
                            if (buf.Length <= i) { valid = false; }

                            while (valid)
                            {
                                if (buf[i] == 0x0a)
                                {
                                    bool inheader = false;
                                    for (int j = i + 1; j < buf.Length; j++)
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
                            if (buf.Length <= i) { valid = false; }

                            start = i;
                            while (valid && i < len)
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
                            if (valid)
                            {
                                publickeyblob = Util.fromBase64(buf, start, i - start);
                                if (type == UNKNOWN)
                                {
                                    if (publickeyblob[8] == 'd') { type = DSA; }
                                    else if (publickeyblob[8] == 'r') { type = RSA; }
                                }
                            }
                        }
                        else
                        {
                            if (buf[0] == 's' && buf[1] == 's' && buf[2] == 'h' && buf[3] == '-')
                            {
                                i = 0;
                                while (i < len) { if (buf[i] == ' ')break; i++; } i++;
                                if (i < len)
                                {
                                    start = i;
                                    while (i < len) { if (buf[i] == ' ')break; i++; }
                                    publickeyblob = Util.fromBase64(buf, start, i - start);
                                }
                            }
                        }
                    }
                    catch (Exception ee)
                    {
                    }
                }
            }
            catch (Exception e)
            {
                if (e is JSchException) throw (JSchException)e;
                throw new JSchException(e.Message,e);
            }

            KeyPair kpair = null;
            if (type == DSA) { kpair = new KeyPairDSA(jsch); }
            else if (type == RSA) { kpair = new KeyPairRSA(jsch); }

            if (kpair != null)
            {
                kpair.encrypted = encrypted;
                kpair.publickeyblob = publickeyblob;
                kpair.vendor = vendor;

                if (encrypted)
                {
                    kpair.iv = iv;
                    kpair.data = data;
                }
                else
                {
                    if (kpair.parse(data))
                    {
                        return kpair;
                    }
                    else
                    {
                        throw new JSchException("invalid privatekey: " + prvkey);
                    }
                }
            }

            return kpair;
        }

        static private byte a2b(byte c)
        {
            if ('0' <= c && c <= '9') return (byte)(c - '0');
            return (byte)(c - 'a' + 10);
        }
        static private byte b2a(byte c)
        {
            if (0 <= c && c <= 9) return (byte)(c + '0');
            return (byte)(c - 10 + 'A');
        }

        public virtual void dispose()
        {
            Util.bzero(passphrase);
        }

        public void finalize()
        {
            dispose();
        }
    }
}
