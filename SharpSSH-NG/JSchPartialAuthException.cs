using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class JSchPartialAuthException:JSchException
    {
        public JSchPartialAuthException()
            : base()
        {
        }
        public JSchPartialAuthException(string methods)
            : base(methods)
        {
        }
        public JSchPartialAuthException(string methods, Exception innerException)
            : base(methods, innerException)
        {
        }
        public string getMethods()
        {
            return Message;
        }
    }
}
