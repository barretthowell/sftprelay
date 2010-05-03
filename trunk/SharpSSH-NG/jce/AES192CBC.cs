using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class AES192CBC:AESCBC
    {
        public AES192CBC() : base(24, 16) { }
    }
}
