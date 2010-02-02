using System;

namespace SharpSSH.NG
{
    interface ForwardedTCPIPDaemon
    {
        void setChannel(ChannelForwardedTCPIP channel, InputStream In, OutputStream Out);
        void setArg(object[] arg);
    }
}
