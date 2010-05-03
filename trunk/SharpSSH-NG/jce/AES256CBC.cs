using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG.jce
{
    public class AES256CBC:AESCBC
    {
        public AES256CBC() : base(32, 16) { }
    }
}
