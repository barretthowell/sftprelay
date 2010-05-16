using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SharpSSH.NG
{
    public interface UIKeyboardInteractive
    {
        string[] promptKeyboardInteractive(string destination,
                           string name,
                           string instruction,
                           string[] prompt,
                           bool[] echo);
    }
}
