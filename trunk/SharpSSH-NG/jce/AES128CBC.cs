using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class AES128CBC : AESCBC
    {
        public AES128CBC() : base(16, 16) { }
    }
}
