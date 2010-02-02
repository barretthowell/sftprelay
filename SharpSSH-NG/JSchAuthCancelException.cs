using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    public class JSchAuthCancelException
    {
        
        public JSchAuthCancelException()
            : base()
        {
        }
        public JSchAuthCancelException(string methods)
            : base(methods)
        {
        }
        public JSchAuthCancelException(string methods, Exception innerException)
            : base(methods, innerException)
        {
        }
        public string getMethods()
        {
            return Message;
        }
    }
}
