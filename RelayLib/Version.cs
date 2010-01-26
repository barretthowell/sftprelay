using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Paneidos.Relay
{
    public class Version
    {
        public const string Vendor = "Paneidos Desu";
        public const string Product = "SFTP-Relay";
        public const string VersionString = "0.1";
        public static string[] WelcomeMessage = null;
        static Version()
        {

            Version.WelcomeMessage = new string[]  {
                                                   "-=-=- Welcome to "+Vendor+" "+Product+" "+VersionString+" -=-=-",
                                                   "This is a relay system, anonymous logins will not work.",
                                                   "Please login as user@sftp-host, and use your password.",
                                                   "SSH-keys are not supported yet."
          };
        }
    }
}
