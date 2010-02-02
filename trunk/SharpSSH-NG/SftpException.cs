using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    class SftpException:Exception
    {
        public int id;
        public SftpException(int id, string message)
            : base(message)
        {
            this.id = id;
        }
        public SftpException(int id, string message, Exception innerException)
            : base(message, innerException)
        {
            this.id = id;
        }

    }
}
