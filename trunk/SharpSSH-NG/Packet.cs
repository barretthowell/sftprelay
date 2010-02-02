using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class Packet
    {
        private static Random random = null;
        static void setRandom(Random foo) { random = foo; }

        Buffer buffer;
        byte[] ba4 = new byte[4];
        public Packet(Buffer buffer)
        {
            this.buffer = buffer;
        }
        public void reset()
        {
            buffer.index = 5;
        }
        void padding(int bsize)
        {
            int len = buffer.index;
            int pad = (-len) & (bsize - 1);
            if (pad < bsize)
            {
                pad += bsize;
            }
            len = len + pad - 4;
            uint ulen = (uint)len;
            ba4[0] = (byte)(ulen >> 24);
            ba4[1] = (byte)(ulen >> 16);
            ba4[2] = (byte)(ulen >> 8);
            ba4[3] = (byte)(ulen);
            Array.Copy(ba4, 0, buffer.buffer, 0, 4);
            buffer.buffer[4] = (byte)pad;
            lock (random)
            {
                random.fill(buffer.buffer, buffer.index, pad);
            }
            buffer.skip(pad);
            //buffer.putPad(pad);
            /*
            for(int i=0; i<buffer.index; i++){
            System.err.print(Integer.toHexString(buffer.buffer[i]&0xff)+":");
            }
            System.err.println("");
            */
        }

        int shift(int len, int mac)
        {
            int s = len + 5 + 9;
            int pad = (-s) & 15;
            if (pad < 16) pad += 16;
            s += pad;
            s += mac;

            /**/
            if (buffer.buffer.length < s + buffer.index - 5 - 9 - len)
            {
                byte[] foo = new byte[s + buffer.index - 5 - 9 - len];
                Array.Copy(buffer.buffer, 0, foo, 0, buffer.buffer.length);
                buffer.buffer = foo;
            }
            /**/

            //if(buffer.buffer.length<len+5+9)
            //  System.err.println("buffer.buffer.length="+buffer.buffer.length+" len+5+9="+(len+5+9));

            //if(buffer.buffer.length<s)
            //  System.err.println("buffer.buffer.length="+buffer.buffer.length+" s="+(s));

            Array.Copy(buffer.buffer,
                     len + 5 + 9,
                     buffer.buffer, s, buffer.index - 5 - 9 - len);

            buffer.index = 10;
            buffer.putInt(len);
            buffer.index = len + 5 + 9;
            return s;
        }
        void unshift(byte command, int recipient, int s, int len)
        {
            Array.Copy(buffer.buffer,
                     s,
                     buffer.buffer, 5 + 9, len);
            buffer.buffer[5] = command;
            buffer.index = 6;
            buffer.putInt(recipient);
            buffer.putInt(len);
            buffer.index = len + 5 + 9;
        }
        Buffer getBuffer()
        {
            return buffer;
        }
    }
}
