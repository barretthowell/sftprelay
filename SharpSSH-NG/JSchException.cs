using System;

namespace SharpSSH.NG
{
    public class JSchException : Exception
    {
        public JSchException()
            : base()
        {
        }
        public JSchException(string message)
            : base(message)
        {
        }
        public JSchException(string message, Exception innerException)
            : base(message, innerException)
        {
        }
        public Exception getCause()
        {
            return InnerException;
        }
    }
}
