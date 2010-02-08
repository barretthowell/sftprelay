using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Net;
using System.IO;

namespace SharpSSH.NG
{
    public static class JavaCompat
    {
        public static byte[] getBytes(this string str)
        {
            return Encoding.UTF8.GetBytes(str);
        }
        public static byte[] getBytes(this string str, string encoding)
        {
            return Encoding.GetEncoding(encoding).GetBytes(str);
        }
        public static byte[] getBytes(this string str,Encoding encoding)
        {
            return encoding.GetBytes(str);
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
        public static void Write(this Stream s, byte[] bytes)
        {
            s.Write(bytes, 0, bytes.Length);
        }
        public static void Write(this Stream s, byte bytes)
        {
            s.Write(new byte[] { bytes }, 0, 1);
        }
        public static int Read(this Stream s)
        {
            return s.ReadByte();
        }
        public static bool mkdirs(this DirectoryInfo di)
        {
            if (di.Exists) return true;
            try
            {
                bool res = mkdirs(di.Parent);
                return res;
            }
            catch
            {
                return false;
            }
        }
        public static byte[] getRow(this byte[,] buf, int row)
        {
            byte[] res = new byte[buf.GetLength(1)];
            for (int i = 0; i < res.Length; i++)
                res[i] = buf[row, i];
            return res;
        }
        public static int Available(this Stream s)
        {
            //TODO
            return 0;
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

        internal static int ToInt32Big(byte[] K_S, int i)
        {
            if (BitConverter.IsLittleEndian)
            {
                byte[] tmp = new byte[4];
                tmp[0] = K_S[i + 3];
                tmp[1] = K_S[i + 2];
                tmp[2] = K_S[i + 1];
                tmp[3] = K_S[i];
                return BitConverter.ToInt32(tmp, 0);
            }
            else
            {
                return BitConverter.ToInt32(K_S, i);
            }
        }
        internal static long ToInt64Big(byte[] K_S, int i)
        {
            if (BitConverter.IsLittleEndian)
            {
                byte[] tmp = new byte[8];
                tmp[0] = K_S[i + 7];
                tmp[1] = K_S[i + 6];
                tmp[2] = K_S[i + 5];
                tmp[3] = K_S[i + 4];
                tmp[4] = K_S[i + 3];
                tmp[5] = K_S[i + 2];
                tmp[6] = K_S[i + 1];
                tmp[7] = K_S[i];
                return BitConverter.ToInt64(tmp, 0);
            }
            else
            {
                return BitConverter.ToInt64(K_S, i);
            }
        }
        internal static byte[] GetBytesBig(short k)
        {
            byte[] tmp = BitConverter.GetBytes(k);
            if (BitConverter.IsLittleEndian)
            {
                tmp[1] ^= tmp[0];
                tmp[0] ^= tmp[1];
                tmp[1] ^= tmp[0];
            }
            return tmp;
        }
        internal static byte[] GetBytesBig(int k)
        {
            byte[] tmp = BitConverter.GetBytes(k);
            if (BitConverter.IsLittleEndian)
            {
                tmp[3] ^= tmp[0];
                tmp[0] ^= tmp[3];
                tmp[3] ^= tmp[0];
                tmp[2] ^= tmp[1];
                tmp[1] ^= tmp[2];
                tmp[2] ^= tmp[1];
            }
            return tmp;
        }
        internal static byte[] GetBytesBig(long k)
        {
            byte[] tmp = BitConverter.GetBytes(k);
            if (BitConverter.IsLittleEndian)
            {
                tmp[0] ^= tmp[7];
                tmp[7] ^= tmp[0];
                tmp[0] ^= tmp[7];
                tmp[1] ^= tmp[6];
                tmp[6] ^= tmp[1];
                tmp[1] ^= tmp[6];
                tmp[2] ^= tmp[5];
                tmp[5] ^= tmp[2];
                tmp[2] ^= tmp[5];
                tmp[3] ^= tmp[4];
                tmp[4] ^= tmp[3];
                tmp[3] ^= tmp[4];
            }
            return tmp;
        }
        internal static int ToInt16Big(byte[] K_S, int i)
        {
            if (BitConverter.IsLittleEndian)
            {
                byte[] tmp = new byte[2];
                tmp[0] = K_S[i + 1];
                tmp[1] = K_S[i];
                return BitConverter.ToInt16(tmp, 0);
            }
            else
            {
                return BitConverter.ToInt16(K_S, i);
            }
        }
    }
}
