using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net.Sockets;
using System.Threading;

namespace SharpSSH.NG
{
    class Util
    {

        public static byte[] fromBase64(byte[] buf, int start, int length)
        {
            return Convert.FromBase64String(Encoding.ASCII.GetString(buf, start, length));
        }
        public static byte[] toBase64(byte[] buf, int start, int length)
        {
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(buf, start, length));
        }

        public static string[] split(string foo, string split)
        {
            return foo.Split(new string[] { split }, StringSplitOptions.None);
        }
        public static bool glob(byte[] pattern, byte[] name)
        {
            return glob0(pattern, 0, name, 0);
        }
        static private bool glob0(byte[] pattern, int pattern_index,
                        byte[] name, int name_index)
        {
            if (name.Length > 0 && name[0] == '.')
            {
                if (pattern.Length > 0 && pattern[0] == '.')
                {
                    if (pattern.Length == 2 && pattern[1] == '*') return true;
                    return glob(pattern, pattern_index + 1, name, name_index + 1);
                }
                return false;
            }
            return glob(pattern, pattern_index, name, name_index);
        }
        static private bool glob(byte[] pattern, int pattern_index,
                        byte[] name, int name_index)
        {
            //Console.Error.WriteLine("glob: "+Encoding.UTF8.GetString(pattern)+", "+pattern_index+" "+Encoding.UTF8.GetString(name)+", "+name_index);

            int patternlen = pattern.Length;
            if (patternlen == 0)
                return false;

            int namelen = name.Length;
            int i = pattern_index;
            int j = name_index;

            while (i < patternlen && j < namelen)
            {
                if (pattern[i] == '\\')
                {
                    if (i + 1 == patternlen)
                        return false;
                    i++;
                    if (pattern[i] != name[j])
                        return false;
                    i += skipUTF8Char(pattern[i]);
                    j += skipUTF8Char(name[j]);
                    continue;
                }

                if (pattern[i] == '*')
                {
                    while (i < patternlen)
                    {
                        if (pattern[i] == '*')
                        {
                            i++;
                            continue;
                        }
                        break;
                    }
                    if (patternlen == i)
                        return true;

                    byte foo = pattern[i];
                    if (foo == '?')
                    {
                        while (j < namelen)
                        {
                            if (glob(pattern, i, name, j))
                            {
                                return true;
                            }
                            j += skipUTF8Char(name[j]);
                        }
                        return false;
                    }
                    else if (foo == '\\')
                    {
                        if (i + 1 == patternlen)
                            return false;
                        i++;
                        foo = pattern[i];
                        while (j < namelen)
                        {
                            if (foo == name[j])
                            {
                                if (glob(pattern, i + skipUTF8Char(foo),
                                        name, j + skipUTF8Char(name[j])))
                                {
                                    return true;
                                }
                            }
                            j += skipUTF8Char(name[j]);
                        }
                        return false;
                    }

                    while (j < namelen)
                    {
                        if (foo == name[j])
                        {
                            if (glob(pattern, i, name, j))
                            {
                                return true;
                            }
                        }
                        j += skipUTF8Char(name[j]);
                    }
                    return false;
                }

                if (pattern[i] == '?')
                {
                    i++;
                    j += skipUTF8Char(name[j]);
                    continue;
                }

                if (pattern[i] != name[j])
                    return false;

                i += skipUTF8Char(pattern[i]);
                j += skipUTF8Char(name[j]);

                if (!(j < namelen))
                {         // name is end
                    if (!(i < patternlen))
                    {    // pattern is end
                        return true;
                    }
                    if (pattern[i] == '*')
                    {
                        break;
                    }
                }
                continue;
            }

            if (i == patternlen && j == namelen)
                return true;

            if (!(j < namelen) &&  // name is end
               pattern[i] == '*')
            {
                bool ok = true;
                while (i < patternlen)
                {
                    if (pattern[i++] != '*')
                    {
                        ok = false;
                        break;
                    }
                }
                return ok;
            }

            return false;
        }

        public static string quote(string path)
        {
            byte[] _path = str2byte(path);
            int count = 0;
            for (int i = 0; i < _path.Length; i++)
            {
                byte b = _path[i];
                if (b == '\\' || b == '?' || b == '*')
                    count++;
            }
            if (count == 0)
                return path;
            byte[] _path2 = new byte[_path.Length + count];
            for (int i = 0, j = 0; i < _path.Length; i++)
            {
                byte b = _path[i];
                if (b == '\\' || b == '?' || b == '*')
                {
                    _path2[j++] = (byte)'\\';
                }
                _path2[j++] = b;
            }
            return byte2str(_path2);
        }

        public static string unquote(string path)
        {
            byte[] foo = str2byte(path);
            byte[] bar = unquote(foo);
            if (foo.Length == bar.Length)
                return path;
            return byte2str(bar);
        }
        public static byte[] unquote(byte[] path)
        {
            int pathlen = path.Length;
            int i = 0;
            while (i < pathlen)
            {
                if (path[i] == '\\')
                {
                    if (i + 1 == pathlen)
                        break;
                    Array.Copy(path, i + 1, path, i, path.Length - (i + 1));
                    pathlen--;
                    i++;
                    continue;
                }
                i++;
            }
            if (pathlen == path.Length)
                return path;
            byte[] foo = new byte[pathlen];
            Array.Copy(path, 0, foo, 0, pathlen);
            return foo;
        }

        private static string[] chars ={
    "0","1","2","3","4","5","6","7","8","9", "a","b","c","d","e","f"
  };
        public static string getFingerPrint(HASH hash, byte[] data)
        {
            try
            {
                hash.init();
                hash.update(data, 0, data.Length);
                byte[] foo = hash.digest();
                StringBuilder sb = new StringBuilder();
                int bar;
                for (int i = 0; i < foo.Length; i++)
                {
                    bar = foo[i] & 0xff;
                    sb.Append(chars[(((uint)bar) >> 4) & 0xf]);
                    sb.Append(chars[(bar) & 0xf]);
                    if (i + 1 < foo.Length)
                        sb.Append(":");
                }
                return sb.ToString();
            }
            catch //(Exception e)
            {
                return "???";
            }
        }
        public static bool array_equals(byte[] foo, byte[] bar)
        {
            int i = foo.Length;
            if (i != bar.Length) return false;
            for (int j = 0; j < i; j++) { if (foo[j] != bar[j]) return false; }
            //try{while(true){i--; if(foo[i]!=bar[i])return false;}}catch(Exception e){}
            return true;
        }
        public static TcpClient createSocket(string host, int port, int timeout)
        {
            TcpClient socket = null;
            if (timeout == 0)
            {
                try
                {
                    socket = new TcpClient(host, port);
                    return socket;
                }
                catch (Exception e)
                {
                    throw new JSchException(e.Message,e);
                }
            }
            string _host = host;
            int _port = port;
            TcpClient[] sockp = new TcpClient[1];
            Exception[] ee = new Exception[1];
            string message = "";
            Thread tmp = new Thread(new ThreadStart(delegate()
            {

                sockp[0] = null;
                try
                {
                    sockp[0] = new TcpClient(_host, _port);
                }
                catch (Exception e)
                {
                    ee[0] = e;
                    if (sockp[0] != null && sockp[0].Connected)
                    {
                        try
                        {
                            sockp[0].Close();
                        }
                        catch /*(Exception eee)*/ { }
                    }
                    sockp[0] = null;
                }

            }));
            tmp.Name = "Opening Socket " + host;
            tmp.Start();
            try
            {
                tmp.Join(timeout);
                message = "timeout: ";
            }
            catch
            {
            }
            if (sockp[0] != null && sockp[0].Connected)
            {
                socket = sockp[0];
            }
            else
            {
                message += "socket is not established";
                if (ee[0] != null)
                {
                    message = ee[0].ToString();
                }
                tmp.Interrupt();
                tmp = null;
                throw new JSchException(message);
            }
            return socket;
        }

        public static byte[] str2byte(string str, string encoding)
        {
            if (str == null)
                return null;
            try { return str.getBytes(Encoding.GetEncoding(encoding)); }
            catch //(Exception e)
            {
                return str.getBytes();
            }
        }

        public static byte[] str2byte(string str)
        {
            return str2byte(str, "UTF-8");
        }

        public static string byte2str(byte[] str, string encoding)
        {
            try { return Encoding.GetEncoding(encoding).GetString(str); }
            catch //(Exception e)
            {
                return Encoding.UTF8.GetString(str);
            }
        }

        public static string byte2str(byte[] str)
        {
            return byte2str(str, "UTF-8");
        }

        /*
        static byte[] char2byte(char[] foo){
          int len=0;
          for(int i=0; i<foo.Length; i++){
            if((foo[i]&0xff00)==0) len++;
            else len+=2;
          }
          byte[] bar=new byte[len];
          for(int i=0, j=0; i<foo.Length; i++){
            if((foo[i]&0xff00)==0){
              bar[j++]=(byte)foo[i];
            }
            else{
              bar[j++]=(byte)(foo[i]>>8);
              bar[j++]=(byte)foo[i];
            }
          }
          return bar;
        }
        */
        public static void bzero(byte[] foo)
        {
            if (foo == null)
                return;
            for (int i = 0; i < foo.Length; i++)
                foo[i] = 0;
        }

        public static string diffString(string str, string[] not_available)
        {
            string[] stra = Util.split(str, ",");
            string result = null;
            for (int i = 0; i < stra.Length; i++)
            {
                for (int j = 0; j < not_available.Length; j++)
                {
                    if (stra[i].Equals(not_available[j]))
                    {
                        goto loop;
                    }
                }
                if (result == null) { result = stra[i]; }
                else { result = result + "," + stra[i]; }
            loop:
                new object();
            }
            return result;
        }

        private static int skipUTF8Char(byte b)
        {
            if ((byte)(b & 0x80) == 0) return 1;
            if ((byte)(b & 0xe0) == (byte)0xc0) return 2;
            if ((byte)(b & 0xf0) == (byte)0xe0) return 3;
            return 1;
        }
    }
}