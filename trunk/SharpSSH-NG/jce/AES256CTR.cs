using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class AES256CTR:AESCTR
    {
        public AES256CTR() : base(32, 16) { }
    }
}
