using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class AES192CTR:AESCTR
    {
        public AES192CTR() : base(24, 16) { }
    }
}
