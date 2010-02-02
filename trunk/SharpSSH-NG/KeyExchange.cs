using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    abstract class KeyExchange
    {

        const int PROPOSAL_KEX_ALGS = 0;
        const int PROPOSAL_SERVER_HOST_KEY_ALGS = 1;
        const int PROPOSAL_ENC_ALGS_CTOS = 2;
        const int PROPOSAL_ENC_ALGS_STOC = 3;
        const int PROPOSAL_MAC_ALGS_CTOS = 4;
        const int PROPOSAL_MAC_ALGS_STOC = 5;
        const int PROPOSAL_COMP_ALGS_CTOS = 6;
        const int PROPOSAL_COMP_ALGS_STOC = 7;
        const int PROPOSAL_LANG_CTOS = 8;
        const int PROPOSAL_LANG_STOC = 9;
        const int PROPOSAL_MAX = 10;

        //static string kex_algs="diffie-hellman-group-exchange-sha1"+
        //                       ",diffie-hellman-group1-sha1";

        //static string kex="diffie-hellman-group-exchange-sha1";
        static string kex = "diffie-hellman-group1-sha1";
        static string server_host_key = "ssh-rsa,ssh-dss";
        static string enc_c2s = "blowfish-cbc";
        static string enc_s2c = "blowfish-cbc";
        static string mac_c2s = "hmac-md5";     // hmac-md5,hmac-sha1,hmac-ripemd160,
        // hmac-sha1-96,hmac-md5-96
        static string mac_s2c = "hmac-md5";
        //static string comp_c2s="none";        // zlib
        //static string comp_s2c="none";
        static string lang_c2s = "";
        static string lang_s2c = "";

        public const int STATE_END = 0;

        protected Session session = null;
        protected HASH sha = null;
        protected byte[] K = null;
        protected byte[] H = null;
        protected byte[] K_S = null;

        public abstract void init(Session session,
                      byte[] V_S, byte[] V_C, byte[] I_S, byte[] I_C);
        public abstract bool next(Buffer buf);
        public abstract string getKeyType();
        public abstract int getState();

        /*
        void dump(byte[] foo){
          for(int i=0; i<foo.length; i++){
            if((foo[i]&0xf0)==0)System.err.print("0");
            System.err.print(Integer.toHexString(foo[i]&0xff));
            if(i%16==15){Console.Error.WriteLine(""); continue;}
            if(i%2==1)System.err.print(" ");
          }
        } 
        */

        protected static string[] guess(byte[] I_S, byte[] I_C)
        {
            //Console.Error.WriteLine("guess: ");
            string[] guess = new string[PROPOSAL_MAX];
            Buffer sb = new Buffer(I_S); sb.setOffSet(17);
            Buffer cb = new Buffer(I_C); cb.setOffSet(17);

            for (int i = 0; i < PROPOSAL_MAX; i++)
            {
                byte[] sp = sb.getString();  // server proposal
                byte[] cp = cb.getString();  // client proposal

                //Console.Error.WriteLine("server-proposal: |"+new string(sp)+"|");
                //Console.Error.WriteLine("client-proposal: |"+new string(cp)+"|");

                int j = 0;
                int k = 0;
            //Console.Error.WriteLine(new string(cp));
                while (j < cp.length)
                {
                    while (j < cp.length && cp[j] != ',') j++;
                    if (k == j) return null;
                    string algorithm = new string(cp, k, j - k);
                    //Console.Error.WriteLine("algorithm: "+algorithm);
                    int l = 0;
                    int m = 0;
                    while (l < sp.length)
                    {
                        while (l < sp.length && sp[l] != ',') l++;
                        if (m == l) return null;
                        //Console.Error.WriteLine("  "+new string(sp, m, l-m));
                        if (algorithm.equals(new string(sp, m, l - m)))
                        {
                            guess[i] = algorithm;
                            //Console.Error.WriteLine("  "+algorithm);
                            goto loop;
                        }
                        l++;
                        m = l;
                    }
                    j++;
                    k = j;
                }
            loop:
                if (j == 0)
                {
                    guess[i] = "";
                }
                else if (guess[i] == null)
                {
                    //Console.Error.WriteLine("  fail");
                    return null;
                }
            }

            if (JSch.getLogger().isEnabled(Logger.INFO))
            {
                JSch.getLogger().log(Logger.INFO,
                                     "kex: server->client" +
                                     " " + guess[PROPOSAL_ENC_ALGS_STOC] +
                                     " " + guess[PROPOSAL_MAC_ALGS_STOC] +
                                     " " + guess[PROPOSAL_COMP_ALGS_STOC]);
                JSch.getLogger().log(Logger.INFO,
                                     "kex: client->server" +
                                     " " + guess[PROPOSAL_ENC_ALGS_CTOS] +
                                     " " + guess[PROPOSAL_MAC_ALGS_CTOS] +
                                     " " + guess[PROPOSAL_COMP_ALGS_CTOS]);
            }

            //    for(int i=0; i<PROPOSAL_MAX; i++){
            //      Console.Error.WriteLine("guess: ["+guess[i]+"]");
            //    }

            return guess;
        }

        public string getFingerPrint()
        {
            HASH hash = null;
            try
            {
                Class c = Class.forName(session.getConfig("md5"));
                hash = (HASH)(c.newInstance());
            }
            catch (Exception e) { Console.Error.WriteLine("getFingerPrint: " + e); }
            return Util.getFingerPrint(hash, getHostKey());
        }
        byte[] getK() { return K; }
        byte[] getH() { return H; }
        HASH getHash() { return sha; }
        byte[] getHostKey() { return K_S; }
    }
}
