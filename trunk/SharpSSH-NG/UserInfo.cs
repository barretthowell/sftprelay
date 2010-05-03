using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    public interface UserInfo
    {
        string getPassphrase();
        string getPassword();
        bool promptPassword(string message);
        bool promptPassphrase(string message);
        bool promptYesNo(string message);
        void showMessage(string message);
    }
}
