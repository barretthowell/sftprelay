using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
    }
}
