﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    abstract class Compression
    {
        public const int INFLATER = 0;
        public const int DEFLATER = 1;
        public abstract void init(int type, int level);
        public abstract int compress(byte[] buf, int start, int len);
        public abstract byte[] uncompress(byte[] buf, int start, int[] len);
    }
}
