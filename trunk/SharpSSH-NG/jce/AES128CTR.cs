using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class AES128CTR : AESCTR
    {
        public AES128CTR() : base(16, 16) { }
    }
}
