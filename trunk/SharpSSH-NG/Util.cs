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

        static byte[] fromBase64(byte[] buf, int start, int length)
        {
            return Convert.FromBase64String(Encoding.ASCII.GetChars(buf, start, length));
        }
        static byte[] toBase64(byte[] buf, int start, int length)
        {
            return Encoding.ASCII.GetBytes(Convert.ToBase64String(buf, start, length));
        }

        static string[] split(string foo, string split)
        {
            return foo.Split(new string[] { split }, StringSplitOptions.None);
        }
        static bool glob(byte[] pattern, byte[] name)
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
            //Console.Error.WriteLine("glob: "+new string(pattern)+", "+pattern_index+" "+new string(name)+", "+name_index);

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

        static string quote(string path)
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
                    _path2[j++] = '\\';
                }
                _path2[j++] = b;
            }
            return byte2str(_path2);
        }

        static string unquote(string path)
        {
            byte[] foo = str2byte(path);
            byte[] bar = unquote(foo);
            if (foo.Length == bar.Length)
                return path;
            return byte2str(bar);
        }
        static byte[] unquote(byte[] path)
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
        static string getFingerPrint(HASH hash, byte[] data)
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
            catch (Exception e)
            {
                return "???";
            }
        }
        static bool array_equals(byte[] foo, byte[] bar)
        {
            int i = foo.Length;
            if (i != bar.Length) return false;
            for (int j = 0; j < i; j++) { if (foo[j] != bar[j]) return false; }
            //try{while(true){i--; if(foo[i]!=bar[i])return false;}}catch(Exception e){}
            return true;
        }
        static Socket createSocket(string host, int port, int timeout)
        {
            Socket socket = null;
            if (timeout == 0)
            {
                try
                {
                    socket = new Socket(host, port);
                    return socket;
                }
                catch (Exception e)
                {
                    string message = e.toString();
                    if (e is Throwable)
                        throw new JSchException(message, (Throwable)e);
                    throw new JSchException(message);
                }
            }
            string _host = host;
            int _port = port;
            Socket[] sockp = new Socket[1];
            Exception[] ee = new Exception[1];
            string message = "";
            Thread tmp = new Thread(new ThreadStart(delegate()
            {

                sockp[0] = null;
                try
                {
                    sockp[0] = new Socket(_host, _port);
                }
                catch (Exception e)
                {
                    ee[0] = e;
                    if (sockp[0] != null && sockp[0].isConnected())
                    {
                        try
                        {
                            sockp[0].close();
                        }
                        catch (Exception eee) { }
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
            if (sockp[0] != null && sockp[0].isConnected())
            {
                socket = sockp[0];
            }
            else
            {
                message += "socket is not established";
                if (ee[0] != null)
                {
                    message = ee[0].toString();
                }
                tmp.interrupt();
                tmp = null;
                throw new JSchException(message);
            }
            return socket;
        }

        static byte[] str2byte(string str, string encoding)
        {
            if (str == null)
                return null;
            try { return str.getBytes(encoding); }
            catch (java.io.UnsupportedEncodingException e)
            {
                return str.getBytes();
            }
        }

        static byte[] str2byte(string str)
        {
            return str2byte(str, "UTF-8");
        }

        static string byte2str(byte[] str, string encoding)
        {
            try { return new string(str, encoding); }
            catch (java.io.UnsupportedEncodingException e)
            {
                return new string(str);
            }
        }

        static string byte2str(byte[] str)
        {
            return byte2str(str, "UTF-8");
        }

        /*
        static byte[] char2byte(char[] foo){
          int len=0;
          for(int i=0; i<foo.length; i++){
            if((foo[i]&0xff00)==0) len++;
            else len+=2;
          }
          byte[] bar=new byte[len];
          for(int i=0, j=0; i<foo.length; i++){
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
        static void bzero(byte[] foo)
        {
            if (foo == null)
                return;
            for (int i = 0; i < foo.Length; i++)
                foo[i] = 0;
        }

        static string diffString(string str, string[] not_available)
        {
            string[] stra = Util.split(str, ",");
            string result = null;
            for (int i = 0; i < stra.Length; i++)
            {
                for (int j = 0; j < not_available.Length; j++)
                {
                    if (stra[i].equals(not_available[j]))
                    {
                        goto loop;
                    }
                }
                if (result == null) { result = stra[i]; }
                else { result = result + "," + stra[i]; }
            loop:
                null;
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