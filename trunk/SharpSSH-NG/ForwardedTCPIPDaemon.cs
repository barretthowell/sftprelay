using System;
using System.IO;

namespace SharpSSH.NG
{
    interface ForwardedTCPIPDaemon
    {
        void setChannel(ChannelForwardedTCPIP channel, Stream In, Stream Out);
        void setArg(object[] arg);
    }
}
