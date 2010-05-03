using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SharpSSH.NG
{
    class PipedMemoryStream : MemoryStream
    {
        private long m_ReadPosition = 0;
        public long ReadPosition { get { return m_ReadPosition; } set { m_ReadPosition = value; } }


        public PipedMemoryStream()
            : base()
        {
        }

        public PipedMemoryStream(int capacity)
            : base(capacity)
        {
        }

        public long Available()
        {
            return Position - ReadPosition;
        }

        public override void WriteByte(byte value)
        {
            lock (this)
            {
                base.WriteByte(value);
            }
        }
        public override void Write(byte[] buffer, int offset, int count)
        {
            lock (this)
            {
                base.Write(buffer, offset, count);
            }
        }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int res;
            lock (this)
            {
                long tmpPos = Position;
                Position = ReadPosition;
                res = base.Read(buffer, offset, count);
                ReadPosition = Position;
                Position = tmpPos;
            }
            return res;
        }
        public override int ReadByte()
        {
            int res;
            lock (this)
            {
                long tmpPos = Position;
                Position = ReadPosition;
                res = base.ReadByte();
                ReadPosition = Position;
                Position = tmpPos;
            }
            return res;
        }
    }
}
