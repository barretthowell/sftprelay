using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SharpSSH.NG
{
    class IO
    {
        Stream In;
        Stream Out;
        Stream out_ext;

        private bool in_dontclose = false;
        private bool out_dontclose = false;
        private bool out_ext_dontclose = false;

        void setOutputStream(Stream Out) { this.Out = Out; }
        void setOutputStream(Stream Out, bool dontclose)
        {
            this.out_dontclose = dontclose;
            setOutputStream(Out);
        }
        void setExtOutputStream(Stream Out) { this.out_ext = Out; }
        void setExtOutputStream(Stream Out, bool dontclose)
        {
            this.out_ext_dontclose = dontclose;
            setExtOutputStream(Out);
        }
        void setInputStream(Stream In) { this.In = In; }
        void setInputStream(Stream In, bool dontclose)
        {
            this.in_dontclose = dontclose;
            setInputStream(In);
        }

        public void put(Packet p)
        {
            Out.Write(p.buffer.buffer, 0, p.buffer.index);
            Out.Flush();
        }
        void put(byte[] array, int begin, int length)
        {
            Out.Write(array, begin, length);
            Out.Flush();
        }
        void put_ext(byte[] array, int begin, int length)
        {
            out_ext.Write(array, begin, length);
            out_ext.Flush();
        }

        int getByte()
        {
            return In.ReadByte();
        }

        void getByte(byte[] array)
        {
            getByte(array, 0, array.Length);
        }

        void getByte(byte[] array, int begin, int length)
        {
            do
            {
                int completed = In.Read(array, begin, length);
                if (completed < 0)
                {
                    throw new IOException("End of IO Stream Read");
                }
                begin += completed;
                length -= completed;
            }
            while (length > 0);
        }

        void out_close()
        {
            try
            {
                if (Out != null && !out_dontclose) Out.Close();
                Out = null;
            }
            catch (Exception ee) { }
        }

        public void close()
        {
            try
            {
                if (In != null && !in_dontclose) In.Close();
                In = null;
            }
            catch (Exception ee) { }

            out_close();

            try
            {
                if (out_ext != null && !out_ext_dontclose) out_ext.Close();
                out_ext = null;
            }
            catch (Exception ee) { }
        }

        /*
        public void finalize() {
          try{
            if(In!=null) In.close();
          }
          catch(Exception ee){}
          try{
            if(Out!=null) Out.close();
          }
          catch(Exception ee){}
          try{
            if(out_ext!=null) out_ext.close();
          }
          catch(Exception ee){}
        }
        */
    }
}
