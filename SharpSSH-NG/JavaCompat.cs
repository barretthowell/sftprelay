using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Net;

namespace SharpSSH.NG
{
    public static class JavaCompat
    {
        public static byte[] getBytes(this string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }
        public static bool regionMatches(this string str, int toffset, string other, int ooffset, int len)
        {
            return str.regionMatches(false, toffset, other, ooffset, len);
        }
        public static bool regionMatches(this string str, bool ignoreCase, int toffset, string other, int ooffset, int len)
        {
            if (toffset < 0 || ooffset < 0) return false;
            if (toffset + len > str.Length) return false;
            if (ooffset + len > other.Length) return false;
            try
            {
                if (string.Compare(str, toffset, other, ooffset, len, ignoreCase) == 0) return true;
                return false;
            }
            catch
            {
                return false;
            }
        }
        public static string RemoteHost(this Socket socket)
        {
            if (socket.RemoteEndPoint is IPEndPoint)
            {
                IPEndPoint ipep = (IPEndPoint)socket.RemoteEndPoint;
                return ipep.Address.ToString();
            }
            throw new InvalidCastException();

        }
        private static DateTime Jan1st1970 = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        public static long CurrentTimeMillis()
        {
            return (long)((DateTime.UtcNow - Jan1st1970).TotalMilliseconds);
        }
        public static void setSoTimeout(this TcpClient t, int timeout)
        {
            t.ReceiveTimeout = timeout;
            t.SendTimeout = timeout;
        }
        public static int RemotePort(this Socket socket)
        {
            if (socket.RemoteEndPoint is IPEndPoint)
            {
                IPEndPoint ipep = (IPEndPoint)socket.RemoteEndPoint;
                return ipep.Port;
            }
            throw new InvalidCastException();
        }
        public static object newInstance(this Type t)
        {
            return Activator.CreateInstance(t);
        }
    }
}
