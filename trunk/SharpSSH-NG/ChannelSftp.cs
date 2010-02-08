using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

namespace SharpSSH.NG
{
    class ChannelSftp : ChannelSession
    {
        private const byte SSH_FXP_INIT = 1;
        private const byte SSH_FXP_VERSION = 2;
        private const byte SSH_FXP_OPEN = 3;
        private const byte SSH_FXP_CLOSE = 4;
        private const byte SSH_FXP_READ = 5;
        private const byte SSH_FXP_WRITE = 6;
        private const byte SSH_FXP_LSTAT = 7;
        private const byte SSH_FXP_FSTAT = 8;
        private const byte SSH_FXP_SETSTAT = 9;
        private const byte SSH_FXP_FSETSTAT = 10;
        private const byte SSH_FXP_OPENDIR = 11;
        private const byte SSH_FXP_READDIR = 12;
        private const byte SSH_FXP_REMOVE = 13;
        private const byte SSH_FXP_MKDIR = 14;
        private const byte SSH_FXP_RMDIR = 15;
        private const byte SSH_FXP_REALPATH = 16;
        private const byte SSH_FXP_STAT = 17;
        private const byte SSH_FXP_RENAME = 18;
        private const byte SSH_FXP_READLINK = 19;
        private const byte SSH_FXP_SYMLINK = 20;
        private const byte SSH_FXP_STATUS = 101;
        private const byte SSH_FXP_HANDLE = 102;
        private const byte SSH_FXP_DATA = 103;
        private const byte SSH_FXP_NAME = 104;
        private const byte SSH_FXP_ATTRS = 105;
        private const byte SSH_FXP_EXTENDED = (byte)200;
        private const byte SSH_FXP_EXTENDED_REPLY = (byte)201;

        // pflags
        private const int SSH_FXF_READ = 0x00000001;
        private const int SSH_FXF_WRITE = 0x00000002;
        private const int SSH_FXF_APPEND = 0x00000004;
        private const int SSH_FXF_CREAT = 0x00000008;
        private const int SSH_FXF_TRUNC = 0x00000010;
        private const int SSH_FXF_EXCL = 0x00000020;

        private const int SSH_FILEXFER_ATTR_SIZE = 0x00000001;
        private const int SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
        private const int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
        private const int SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008;
        private const int SSH_FILEXFER_ATTR_EXTENDED = unchecked((int)0x80000000);
        

        public const int SSH_FX_OK = 0;
        public const int SSH_FX_EOF = 1;
        public const int SSH_FX_NO_SUCH_FILE = 2;
        public const int SSH_FX_PERMISSION_DENIED = 3;
        public const int SSH_FX_FAILURE = 4;
        public const int SSH_FX_BAD_MESSAGE = 5;
        public const int SSH_FX_NO_CONNECTION = 6;
        public const int SSH_FX_CONNECTION_LOST = 7;
        public const int SSH_FX_OP_UNSUPPORTED = 8;
        /*
           SSH_FX_OK
              Indicates successful completion of the operation.
           SSH_FX_EOF
             indicates end-of-file condition; for SSH_FX_READ it means that no
               more data is available in the file, and for SSH_FX_READDIR it
              indicates that no more files are contained in the directory.
           SSH_FX_NO_SUCH_FILE
              is returned when a reference is made to a file which should exist
              but doesn't.
           SSH_FX_PERMISSION_DENIED
              is returned when the authenticated user does not have sufficient
              permissions to perform the operation.
           SSH_FX_FAILURE
              is a generic catch-all error message; it should be returned if an
              error occurs for which there is no more specific error code
              defined.
           SSH_FX_BAD_MESSAGE
              may be returned if a badly formatted packet or protocol
              incompatibility is detected.
           SSH_FX_NO_CONNECTION
              is a pseudo-error which indicates that the client has no
              connection to the server (it can only be generated locally by the
              client, and MUST NOT be returned by servers).
           SSH_FX_CONNECTION_LOST
              is a pseudo-error which indicates that the connection to the
              server has been lost (it can only be generated locally by the
              client, and MUST NOT be returned by servers).
           SSH_FX_OP_UNSUPPORTED
              indicates that an attempt was made to perform an operation which
              is not supported for the server (it may be generated locally by
              the client if e.g.  the version number exchange indicates that a
              required feature is not supported by the server, or it may be
              returned by the server if the server does not implement an
              operation).
        */
        private const int MAX_MSG_LENGTH = 256 * 1024;

        public const int OVERWRITE = 0;
        public const int RESUME = 1;
        public const int APPEND = 2;

        //private bool interactive = false;
        private int seq = 1;
        private int[] ackid = new int[1];
        private Buffer buf;
        private Packet packet;

        private int client_version = 3;
        private int server_version = 3;
        private string version;

        private Dictionary<string,string> extensions = null;
        private Stream io_in = null;

        /*
        10. Changes from previous protocol versions
          The SSH File Transfer Protocol has changed over time, before it's
           standardization.  The following is a description of the incompatible
           changes between different versions.
        10.1 Changes between versions 3 and 2
           o  The SSH_FXP_READLINK and SSH_FXP_SYMLINK messages were added.
           o  The SSH_FXP_EXTENDED and SSH_FXP_EXTENDED_REPLY messages were added.
           o  The SSH_FXP_STATUS message was changed to include fields `error
              message' and `language tag'.
        10.2 Changes between versions 2 and 1
           o  The SSH_FXP_RENAME message was added.
        10.3 Changes between versions 1 and 0
           o  Implementation changes, no actual protocol changes.
        */

        private readonly string file_separator = new string(new char[] {Path.DirectorySeparatorChar});
        private readonly char file_separatorc = Path.DirectorySeparatorChar;
        private static bool fs_is_bs = Path.DirectorySeparatorChar == '\\';

        private string cwd;
        private string home;
        private string lcwd;

        private const string UTF8 = "UTF-8";
        private string fEncoding = UTF8;
        private bool fEncoding_is_utf8 = true;

        public ChannelSftp(): base()
        {
            packet = new Packet(buf);
            version = client_version.ToString();
        }

        internal override void init()
        {
        }

        public override void Start()
        {
            try
            {

                MemoryStream pois = new MemoryStream(32 * 1024);
                io.setOutputStream(pois);
                io.setInputStream(pois);

                io_in = io.In;

                if (io_in == null)
                {
                    throw new JSchException("channel is down");
                }

                Request request = new RequestSftp();
                request.request(getSession(), this);

                /*
                      Console.Error.WriteLine("lmpsize: "+lmpsize);
                      Console.Error.WriteLine("lwsize: "+lwsize);
                      Console.Error.WriteLine("rmpsize: "+rmpsize);
                      Console.Error.WriteLine("rwsize: "+rwsize);
                */

                buf = new Buffer(rmpsize);
                packet = new Packet(buf);
                //int i = 0;
                int length;
                int type;
                //byte[] str;

                // send SSH_FXP_INIT
                sendINIT();

                // receive SSH_FXP_VERSION
                Header header = new Header();
                header = MakeHeader(buf, header);
                length = header.Length;
                if (length > MAX_MSG_LENGTH)
                {
                    throw new SftpException(SSH_FX_FAILURE,
                                            "Received message is too long: " + length);
                }
                type = header.type;             // 2 -> SSH_FXP_VERSION
                server_version = header.rid;
                //Console.Error.WriteLine("SFTP protocol server-version="+server_version);
                if (length > 0)
                {
                    extensions = new Dictionary<string,string>();
                    // extension data
                    fill(buf, length);
                    byte[] extension_name = null;
                    byte[] extension_data = null;
                    while (length > 0)
                    {
                        extension_name = buf.getString();
                        length -= (4 + extension_name.Length);
                        extension_data = buf.getString();
                        length -= (4 + extension_data.Length);
                        extensions.Add(Encoding.UTF8.GetString(extension_name), Encoding.UTF8.GetString(extension_data));
                    }
                }

                lcwd = Path.GetFullPath("."); //new File(".").getCanonicalPath();
            }
            catch (Exception e)
            {
                //Console.Error.WriteLine(e);
                if (e is JSchException) throw (JSchException)e;
                throw new JSchException(e.Message,e);
            }
        }

        public void quit() { disconnect(); }
        public void exit() { disconnect(); }
        public void lcd(string path)
        {
            path = localAbsolutePath(path);
            if (Directory.Exists(path))
            {
                try
                {
                    path = Path.GetFullPath(path); // (new File(path)).getCanonicalPath();
                }
                catch /*(Exception e)*/ { }
                lcwd = path;
                return;
            }
            throw new SftpException(SSH_FX_NO_SUCH_FILE, "No such directory");
        }

        public void cd(string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                path = isUnique(path);

                byte[] str = _realpath(path);
                SftpATTRS attr = _stat(str);

                if ((attr.getFlags() & SftpATTRS.SSH_FILEXFER_ATTR_PERMISSIONS) == 0)
                {
                    throw new SftpException(SSH_FX_FAILURE,
                                            "Can't change directory: " + path);
                }
                if (!attr.isDir())
                {
                    throw new SftpException(SSH_FX_FAILURE,
                                            "Can't change directory: " + path);
                }

                setCwd(Util.byte2str(str, fEncoding));
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void put(string src, string dst)
        {
            put(src, dst, null, OVERWRITE);
        }
        public void put(string src, string dst, int mode)
        {
            put(src, dst, null, mode);
        }
        public void put(string src, string dst,
                SftpProgressMonitor monitor)
        {
            put(src, dst, monitor, OVERWRITE);
        }
        public void put(string src, string dst,
                SftpProgressMonitor monitor, int mode)
        {
            src = localAbsolutePath(src);
            dst = remoteAbsolutePath(dst);

            //Console.Error.WriteLine("src: "+src+", "+dst);
            try
            {

                List<string> v = glob_remote(dst);
                int vsize = v.Count;
                if (vsize != 1)
                {
                    if (vsize == 0)
                    {
                        if (isPattern(dst))
                            throw new SftpException(SSH_FX_FAILURE, dst);
                        else
                            dst = Util.unquote(dst);
                    }
                    throw new SftpException(SSH_FX_FAILURE, v.ToString());
                }
                else
                {
                    dst = v[0];
                }

                bool _isRemoteDir = isRemoteDir(dst);

                v = glob_local(src);
                vsize = v.Count;

                StringBuilder dstsb = null;
                if (_isRemoteDir)
                {
                    if (!dst.EndsWith("/"))
                    {
                        dst += "/";
                    }
                    dstsb = new StringBuilder(dst);
                }
                else if (vsize > 1)
                {
                    throw new SftpException(SSH_FX_FAILURE,
                                            "Copying multiple files, but the destination is missing or a file.");
                }

                for (int j = 0; j < vsize; j++)
                {
                    string _src = (string)(v[j]);
                    string _dst = null;
                    if (_isRemoteDir)
                    {
                        int i = _src.LastIndexOf(file_separatorc);
                        if (fs_is_bs)
                        {
                            int ii = _src.LastIndexOf('/');
                            if (ii != -1 && ii > i)
                                i = ii;
                        }
                        if (i == -1) dstsb.Append(_src);
                        else dstsb.Append(_src.Substring(i + 1));
                        _dst = dstsb.ToString();
                        dstsb.Remove(dst.Length, _dst.Length);
                    }
                    else
                    {
                        _dst = dst;
                    }
                    //Console.Error.WriteLine("_dst "+_dst);

                    long size_of_dst = 0;
                    if (mode == RESUME)
                    {
                        try
                        {
                            SftpATTRS attr = _stat(_dst);
                            size_of_dst = attr.getSize();
                        }
                        catch //(Exception eee)
                        {
                            //Console.Error.WriteLine(eee);
                        }
                        long size_of_src = new FileInfo(_src).Length;
                        if (size_of_src < size_of_dst)
                        {
                            throw new SftpException(SSH_FX_FAILURE,
                                                        "failed to resume for " + _dst);
                        }
                        if (size_of_src == size_of_dst)
                        {
                            return;
                        }
                    }

                    if (monitor != null)
                    {
                        monitor.init(SftpProgressMonitor.PUT, _src, _dst,
                                 (new FileInfo(_src)).Length);
                        if (mode == RESUME)
                        {
                            monitor.count(size_of_dst);
                        }
                    }
                    FileStream fis = null;
                    try
                    {
                        fis = new FileStream(_src,FileMode.Open);
                        _put(fis, _dst, monitor, mode);
                    }
                    finally
                    {
                        if (fis != null)
                        {
                            fis.Close();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, e.Message,e);
            }
        }
        public void put(Stream src, string dst)
        {
            put(src, dst, null, OVERWRITE);
        }
        public void put(Stream src, string dst, int mode)
        {
            put(src, dst, null, mode);
        }
        public void put(Stream src, string dst,
                SftpProgressMonitor monitor)
        {
            put(src, dst, monitor, OVERWRITE);
        }
        public void put(Stream src, string dst,
                SftpProgressMonitor monitor, int mode)
        {
            try
            {
                dst = remoteAbsolutePath(dst);

                List<string> v = glob_remote(dst);
                int vsize = v.Count;
                if (vsize != 1)
                {
                    if (vsize == 0)
                    {
                        if (isPattern(dst))
                            throw new SftpException(SSH_FX_FAILURE, dst);
                        else
                            dst = Util.unquote(dst);
                    }
                    throw new SftpException(SSH_FX_FAILURE, v.ToString());
                }
                else
                {
                    dst = v[0];
                }

                if (isRemoteDir(dst))
                {
                    throw new SftpException(SSH_FX_FAILURE, dst + " is a directory");
                }

                _put(src, dst, monitor, mode);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, e.Message,e);
            }
        }

        public void _put(Stream src, string dst,
                SftpProgressMonitor monitor, int mode)
        {
            try
            {
                byte[] dstb = Util.str2byte(dst, fEncoding);
                long skip = 0;
                if (mode == RESUME || mode == APPEND)
                {
                    try
                    {
                        SftpATTRS attr = _stat(dstb);
                        skip = attr.getSize();
                    }
                    catch //(Exception eee)
                    {
                        //Console.Error.WriteLine(eee);
                    }
                }
                if (mode == RESUME && skip > 0)
                {
                    long skipped = src.Seek(skip,SeekOrigin.Current);
                    if (skipped < skip)
                    {
                        throw new SftpException(SSH_FX_FAILURE, "failed to resume for " + dst);
                    }
                }

                if (mode == OVERWRITE) { sendOPENW(dstb); }
                else { sendOPENA(dstb); }

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE)
                {
                    throw new SftpException(SSH_FX_FAILURE, "invalid type=" + type);
                }
                if (type == SSH_FXP_STATUS)
                {
                    int i = buf.getInt();
                    throwStatusError(buf, i);
                }
                byte[] handle = buf.getString();         // handle
                byte[] data = null;

                bool dontcopy = true;

                if (!dontcopy)
                {
                    data = new byte[buf.buffer.Length
                                  - (5 + 13 + 21 + handle.Length
                                    + 32 + 20 // padding and mac
                                    )
                    ];
                }

                long offset = 0;
                if (mode == RESUME || mode == APPEND)
                {
                    offset += skip;
                }

                int startid = seq;
                int _ackid = seq;
                int ackcount = 0;
                while (true)
                {
                    int nread = 0;
                    int s = 0;
                    int datalen = 0;
                    int count = 0;

                    if (!dontcopy)
                    {
                        datalen = data.Length - s;
                    }
                    else
                    {
                        data = buf.buffer;
                        s = 5 + 13 + 21 + handle.Length;
                        datalen = buf.buffer.Length - s
                          - 32 - 20; // padding and mac
                    }

                    do
                    {
                        nread = src.Read(data, s, datalen);
                        if (nread > 0)
                        {
                            s += nread;
                            datalen -= nread;
                            count += nread;
                        }
                    }
                    while (datalen > 0 && nread > 0);
                    if (count <= 0) break;

                    int _i = count;
                    while (_i > 0)
                    {
                        _i -= sendWRITE(handle, offset, data, 0, _i);
                        if ((seq - 1) == startid ||
                           io_in.Available() >= 1024)
                        {
                            while (io_in.Available() > 0)
                            {
                                if (checkStatus(ackid, header))
                                {
                                    _ackid = ackid[0];
                                    if (startid > _ackid || _ackid > seq - 1)
                                    {
                                        if (_ackid == seq)
                                        {
                                            Console.Error.WriteLine("ack error: startid=" + startid + " seq=" + seq + " _ackid=" + _ackid);
                                        }
                                        else
                                        {
                                            //throw new SftpException(SSH_FX_FAILURE, "ack error:");
                                            throw new SftpException(SSH_FX_FAILURE, "ack error: startid=" + startid + " seq=" + seq + " _ackid=" + _ackid);
                                        }
                                    }
                                    ackcount++;
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                    offset += count;
                    if (monitor != null && !monitor.count(count))
                    {
                        break;
                    }
                }
                int _ackcount = seq - startid;
                while (_ackcount > ackcount)
                {
                    if (!checkStatus(null, header))
                    {
                        break;
                    }
                    ackcount++;
                }
                if (monitor != null) monitor.end();
                _sendCLOSE(handle, header);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, e.Message,e);
            }
        }

        public Stream put(string dst)
        {
            return put(dst, (SftpProgressMonitor)null, OVERWRITE);
        }
        public Stream put(string dst, int mode)
        {
            return put(dst, (SftpProgressMonitor)null, mode);
        }
        public Stream put(string dst, SftpProgressMonitor monitor, int mode)
        {
            return put(dst, monitor, mode, 0);
        }
        public Stream put(string dst, SftpProgressMonitor monitor, int mode, long offset)
        {
            dst = remoteAbsolutePath(dst);
            try
            {

                dst = isUnique(dst);

                if (isRemoteDir(dst))
                {
                    throw new SftpException(SSH_FX_FAILURE, dst + " is a directory");
                }

                byte[] dstb = Util.str2byte(dst, fEncoding);

                long skip = 0;
                if (mode == RESUME || mode == APPEND)
                {
                    try
                    {
                        SftpATTRS attr = _stat(dstb);
                        skip = attr.getSize();
                    }
                    catch //(Exception eee)
                    {
                        //Console.Error.WriteLine(eee);
                    }
                }

                if (mode == OVERWRITE) { sendOPENW(dstb); }
                else { sendOPENA(dstb); }

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                if (type == SSH_FXP_STATUS)
                {
                    int i = buf.getInt();
                    throwStatusError(buf, i);
                }
                byte[] handle = buf.getString();         // handle

                if (mode == RESUME || mode == APPEND)
                {
                    offset += skip;
                }

                long[] _offset = new long[1];
                _offset[0] = offset;
                Stream Out = new PrivateOutputStream(this,_offset,monitor,handle);
                return Out;
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }
        class PrivateOutputStream : Stream
        {
            private bool init = true;
            private bool isClosed = false;
            private int[] ackid = new int[1];
            private int startid = 0;
            private int _ackid = 0;
            private int ackcount = 0;
            private int writecount = 0;
            private Header header = new Header();
            private ChannelSftp channel;
            private long[] _offset;
            private SftpProgressMonitor monitor;
            private byte[] handle;

            internal PrivateOutputStream(ChannelSftp channel,long[] _offset,SftpProgressMonitor monitor,byte[] handle)
            {
                this.channel = channel;
                this._offset = _offset;
                this.monitor = monitor;
                this.handle = handle;
            }

            public void Write(byte[] d)
            {
                Write(d, 0, d.Length);
            }

            public override void Write(byte[] d, int s, int len)
            {
                if (init)
                {
                    startid = channel.seq;
                    _ackid = channel.seq;
                    init = false;
                }

                if (isClosed)
                {
                    throw new IOException("stream already closed");
                }

                try
                {
                    int _len = len;
                    while (_len > 0)
                    {
                        int sent = channel.sendWRITE(handle, _offset[0], d, s, _len);
                        writecount++;
                        _offset[0] += sent;
                        s += sent;
                        _len -= sent;
                        if ((channel.seq - 1) == startid ||
                           channel.io_in.Available() >= 1024)
                        {
                            while (channel.io_in.Available() > 0)
                            {
                                if (channel.checkStatus(ackid, header))
                                {
                                    _ackid = ackid[0];
                                    if (startid > _ackid || _ackid > channel.seq - 1)
                                    {
                                        throw new SftpException(SSH_FX_FAILURE, "");
                                    }
                                    ackcount++;
                                }
                                else
                                {
                                    break;
                                }
                            }
                        }
                    }
                    if (monitor != null && !monitor.count(len))
                    {
                        Close();
                        throw new IOException("canceled");
                    }
                }
                catch (IOException e) { throw e; }
                catch (Exception e) { throw new IOException(e.ToString()); }
            }

            byte[] _data = new byte[1];
            public void write(int foo)
            {
                _data[0] = (byte)foo;
                Write(_data, 0, 1);
            }

            public override void Flush()
            {

                if (isClosed)
                {
                    throw new IOException("stream already closed");
                }

                if (!init)
                {
                    try
                    {
                        while (writecount > ackcount)
                        {
                            if (!channel.checkStatus(null, header))
                            {
                                break;
                            }
                            ackcount++;
                        }
                    }
                    catch (SftpException e)
                    {
                        throw new IOException(e.ToString());
                    }
                }
            }

            public override void Close()
            {
                if (isClosed)
                {
                    return;
                }
                Flush();
                if (monitor != null) monitor.end();
                try { channel._sendCLOSE(handle, header); }
                catch (IOException e) { throw e; }
                catch (Exception e)
                {
                    throw new IOException(e.ToString());
                }
                isClosed = true;
            }

            public override bool CanRead
            {
                get { return false; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return true; }
            }

            public override long Length
            {
                get { throw new NotImplementedException(); }
            }

            public override long Position
            {
                get
                {
                    throw new NotImplementedException();
                }
                set
                {
                    throw new NotImplementedException();
                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }
        }
        public void get(string src, string dst)
        {
            get(src, dst, null, OVERWRITE);
        }
        public void get(string src, string dst,
                SftpProgressMonitor monitor)
        {
            get(src, dst, monitor, OVERWRITE);
        }
        public void get(string src, string dst,
                SftpProgressMonitor monitor, int mode)
        {
            // System.Out.println("get: "+src+" "+dst);

            src = remoteAbsolutePath(src);
            dst = localAbsolutePath(dst);

            try
            {
                List<string> v = glob_remote(src);
                int vsize = v.Count;
                if (vsize == 0)
                {
                    throw new SftpException(SSH_FX_NO_SUCH_FILE, "No such file");
                }

                //File dstFile = new File(dst);
                bool isDstDir = Directory.Exists(dst);
                StringBuilder dstsb = null;
                if (isDstDir)
                {
                    if (!dst.EndsWith(file_separator))
                    {
                        dst += file_separator;
                    }
                    dstsb = new StringBuilder(dst);
                }
                else if (vsize > 1)
                {
                    throw new SftpException(SSH_FX_FAILURE,
                                            "Copying multiple files, but destination is missing or a file.");
                }

                for (int j = 0; j < vsize; j++)
                {
                    string _src = v[j];
                    SftpATTRS attr = _stat(_src);
                    if (attr.isDir())
                    {
                        throw new SftpException(SSH_FX_FAILURE,
                                                "not supported to get directory " + _src);
                    }

                    string _dst = null;
                    if (isDstDir)
                    {
                        int i = _src.LastIndexOf('/');
                        if (i == -1) dstsb.Append(_src);
                        else dstsb.Append(_src.Substring(i + 1));
                        _dst = dstsb.ToString();
                        dstsb.Remove(dst.Length, _dst.Length);
                    }
                    else
                    {
                        _dst = dst;
                    }

                    if (mode == RESUME)
                    {
                        long size_of_src = attr.getSize();
                        long size_of_dst = new FileInfo(_dst).Length;
                        if (size_of_dst > size_of_src)
                        {
                            throw new SftpException(SSH_FX_FAILURE,
                                                        "failed to resume for " + _dst);
                        }
                        if (size_of_dst == size_of_src)
                        {
                            return;
                        }
                    }

                    if (monitor != null)
                    {
                        monitor.init(SftpProgressMonitor.GET, _src, _dst, attr.getSize());
                        if (mode == RESUME)
                        {
                            monitor.count(new FileInfo(_dst).Length);
                        }
                    }

                    FileStream fos = null;
                    try
                    {
                        if (mode == OVERWRITE)
                        {
                            fos = File.Open(_dst,FileMode.OpenOrCreate);
                        }
                        else
                        {
                            fos = File.Open(_dst,FileMode.Append); // append
                        }
                        // Console.Error.WriteLine("_get: "+_src+", "+_dst);
                        _get(_src, fos, monitor, mode, new FileInfo(_dst).Length);
                    }
                    finally
                    {
                        if (fos != null)
                        {
                            fos.Close();
                        }
                    }
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }
        public void get(string src, Stream dst)
        {
            get(src, dst, null, OVERWRITE, 0);
        }
        public void get(string src, Stream dst,
                SftpProgressMonitor monitor)
        {
            get(src, dst, monitor, OVERWRITE, 0);
        }
        public void get(string src, Stream dst,
                 SftpProgressMonitor monitor, int mode, long skip)
        {
            //Console.Error.WriteLine("get: "+src+", "+dst);
            try
            {
                src = remoteAbsolutePath(src);

                src = isUnique(src);

                if (monitor != null)
                {
                    SftpATTRS attr = _stat(src);
                    monitor.init(SftpProgressMonitor.GET, src, "??", attr.getSize());
                    if (mode == RESUME)
                    {
                        monitor.count(skip);
                    }
                }
                _get(src, dst, monitor, mode, skip);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        private void _get(string src, Stream dst,
                          SftpProgressMonitor monitor, int mode, long skip)
        {
            //Console.Error.WriteLine("_get: "+src+", "+dst);

            byte[] srcb = Util.str2byte(src, fEncoding);
            try
            {
                sendOPENR(srcb);

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }

                if (type == SSH_FXP_STATUS)
                {
                    int i = buf.getInt();
                    throwStatusError(buf, i);
                }

                byte[] handle = buf.getString();         // filename

                long offset = 0;
                if (mode == RESUME)
                {
                    offset += skip;
                }

                int request_len = 0;
                //loop:
                while (true)
                {

                    request_len = buf.buffer.Length - 13;
                    if (server_version == 0) { request_len = 1024; }
                    sendREAD(handle, offset, request_len);

                    header = MakeHeader(buf, header);
                    length = header.Length;
                    type = header.type;
                    int i;
                    if (type == SSH_FXP_STATUS)
                    {
                        fill(buf, length);
                        i = buf.getInt();
                        if (i == SSH_FX_EOF)
                        {
                            goto outloop;
                        }
                        throwStatusError(buf, i);
                    }

                    if (type != SSH_FXP_DATA)
                    {
                        goto outloop;
                    }

                    buf.rewind();
                    fill(buf.buffer, 0, 4); length -= 4;
                    i = buf.getInt();   // length of data 
                    int foo = i;

                    while (foo > 0)
                    {
                        int bar = foo;
                        if (bar > buf.buffer.Length)
                        {
                            bar = buf.buffer.Length;
                        }
                        i = io_in.Read(buf.buffer, 0, bar);
                        if (i < 0)
                        {
                            goto outloop; //loop;
                        }
                        int data_len = i;
                        dst.Write(buf.buffer, 0, data_len);

                        offset += data_len;
                        foo -= data_len;

                        if (monitor != null)
                        {
                            if (!monitor.count(data_len))
                            {
                                while (foo > 0)
                                {
                                    i = io_in.Read(buf.buffer,
                                                 0,
                                                 (buf.buffer.Length < foo ? buf.buffer.Length : foo));
                                    if (i <= 0) break;
                                    foo -= i;
                                }
                                goto outloop; //loop;
                            }
                        }

                    }
                    //Console.Error.WriteLine("length: "+length);  // length should be 0
                }
            outloop:
                dst.Flush();

                if (monitor != null) monitor.end();
                _sendCLOSE(handle, header);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public Stream get(string src)
        {
            return get(src, null, 0L);
        }
        public Stream get(string src, SftpProgressMonitor monitor)
        {
            return get(src, monitor, 0L);
        }

        /**
         * @deprecated  This method will be deleted in the future.
         */
        public Stream get(string src, int mode)
        {
            return get(src, null, 0L);
        }
        /**
         * @deprecated  This method will be deleted in the future.
         */
        public Stream get(string src, SftpProgressMonitor monitor, int mode)
        {
            return get(src, monitor, 0L);
        }
        public Stream get(string src, SftpProgressMonitor monitor, long skip)
        {
            src = remoteAbsolutePath(src);
            try
            {
                src = isUnique(src);

                byte[] srcb = Util.str2byte(src, fEncoding);

                SftpATTRS attr = _stat(srcb);
                if (monitor != null)
                {
                    monitor.init(SftpProgressMonitor.GET, src, "??", attr.getSize());
                }

                sendOPENR(srcb);

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                if (type == SSH_FXP_STATUS)
                {
                    int i = buf.getInt();
                    throwStatusError(buf, i);
                }

                byte[] handle = buf.getString();         // handle

                Stream In = new PrivateInputStream(this,monitor,skip,handle);
                return In;
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }
        class PrivateInputStream:Stream
        {
            long offset = 0;
            bool closed = false;
            int rest_length = 0;
            byte[] _data = new byte[1];
            byte[] rest_byte = new byte[1024];
            Header header = new Header();

            SftpProgressMonitor monitor;
            ChannelSftp channel;
            byte[] handle;

            internal PrivateInputStream(ChannelSftp channel,SftpProgressMonitor monitor,long offset,byte[] handle)
            {
                this.channel = channel;
                this.monitor = monitor;
                this.offset = offset;
                this.handle = handle;
            }

            public override int ReadByte()
            {
                if (closed) return -1;
                int i = Read(_data, 0, 1);
                if (i == -1) { return -1; }
                else
                {
                    return _data[0] & 0xff;
                }
            }
            public int Read(byte[] d)
            {
                if (closed) return -1;
                return Read(d, 0, d.Length);
            }
            public override int Read(byte[] d, int s, int len)
            {
                if (closed) return -1;
                if (d == null) { throw new NullReferenceException(); }
                if (s < 0 || len < 0 || s + len > d.Length)
                {
                    throw new IndexOutOfRangeException();
                }
                if (len == 0) { return 0; }
                int foo;
                if (rest_length > 0)
                {
                    foo = rest_length;
                    if (foo > len) foo = len;
                    Array.Copy(rest_byte, 0, d, s, foo);
                    if (foo != rest_length)
                    {
                        Array.Copy(rest_byte, foo,
                                         rest_byte, 0, rest_length - foo);
                    }

                    if (monitor != null)
                    {
                        if (!monitor.count(foo))
                        {
                            Close();
                            return -1;
                        }
                    }

                    rest_length -= foo;
                    return foo;
                }

                if (channel.buf.buffer.Length - 13 < len)
                {
                    len = channel.buf.buffer.Length - 13;
                }
                if (channel.server_version == 0 && len > 1024)
                {
                    len = 1024;
                }

                try { channel.sendREAD(handle, offset, len); }
                catch /*(Exception e)*/ { throw new IOException("error"); }

                header = channel.MakeHeader(channel.buf, header);
                rest_length = header.Length;
                int type = header.type;
                int id = header.rid;

                if (type != SSH_FXP_STATUS && type != SSH_FXP_DATA)
                {
                    throw new IOException("error");
                }
                int i;
                if (type == SSH_FXP_STATUS)
                {
                    channel.fill(channel.buf, rest_length);
                    i = channel.buf.getInt();
                    rest_length = 0;
                    if (i == SSH_FX_EOF)
                    {
                        Close();
                        return -1;
                    }
                    //throwStatusError(buf, i);
                    throw new IOException("error");
                }
                channel.buf.rewind();
                channel.fill(channel.buf.buffer, 0, 4);
                i = channel.buf.getInt(); rest_length -= 4;

                offset += rest_length;
                foo = i;
                if (foo > 0)
                {
                    int bar = rest_length;
                    if (bar > len)
                    {
                        bar = len;
                    }
                    i = channel.io_in.Read(d, s, bar);
                    if (i < 0)
                    {
                        return -1;
                    }
                    rest_length -= i;

                    if (rest_length > 0)
                    {
                        if (rest_byte.Length < rest_length)
                        {
                            rest_byte = new byte[rest_length];
                        }
                        int _s = 0;
                        int _len = rest_length;
                        int j;
                        while (_len > 0)
                        {
                            j = channel.io_in.Read(rest_byte, _s, _len);
                            if (j <= 0) break;
                            _s += j;
                            _len -= j;
                        }
                    }

                    if (monitor != null)
                    {
                        if (!monitor.count(i))
                        {
                            Close();
                            return -1;
                        }
                    }

                    return i;
                }
                return 0; // ??
            }
            public override void Close()
            {
                if (closed) return;
                closed = true;
                if (monitor != null) monitor.end();
                try { channel._sendCLOSE(handle, header); }
                catch (Exception ) { throw new IOException("error"); }
            }

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return false; }
            }

            public override void Flush()
            {
                throw new NotImplementedException();
            }

            public override long Length
            {
                get { throw new NotImplementedException(); }
            }

            public override long Position
            {
                get
                {
                    throw new NotImplementedException();
                }
                set
                {
                    throw new NotImplementedException();
                }
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotImplementedException();
            }

            public override void SetLength(long value)
            {
                throw new NotImplementedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotImplementedException();
            }
        }
        public List<LsEntry> ls(string path)
        {
            //System.Out.println("ls: "+path);
            try
            {
                path = remoteAbsolutePath(path);
                byte[] pattern = null;
                //java.util.Vector v = new java.util.Vector();
                List<LsEntry> v = new List<LsEntry>();

                int foo = path.LastIndexOf('/');
                string dir = path.Substring(0, ((foo == 0) ? 1 : foo));
                string _pattern = path.Substring(foo + 1);
                dir = Util.unquote(dir);

                // If pattern has included '*' or '?', we need to convert
                // to UTF-8 string before globbing.
                byte[][] _pattern_utf8 = new byte[1][];
                bool pattern_has_wildcard = isPattern(_pattern, _pattern_utf8);

                if (pattern_has_wildcard)
                {
                    pattern = _pattern_utf8[0];
                }
                else
                {
                    string upath = Util.unquote(path);
                    //SftpATTRS attr=_lstat(upath);
                    SftpATTRS attr = _stat(upath);
                    if (attr.isDir())
                    {
                        pattern = null;
                        dir = upath;
                    }
                    else
                    {
                        /*
                          // If we can generage longname by ourself,
                          // we don't have to use openDIR.
                        string filename=Util.unquote(_pattern);
                        string longname=...
                        v.Add(new LsEntry(filename, longname, attr));
                        return v;
                        */

                        if (fEncoding_is_utf8)
                        {
                            pattern = _pattern_utf8[0];
                            pattern = Util.unquote(pattern);
                        }
                        else
                        {
                            _pattern = Util.unquote(_pattern);
                            pattern = Util.str2byte(_pattern, fEncoding);
                        }

                    }
                }

                sendOPENDIR(Util.str2byte(dir, fEncoding));

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                if (type == SSH_FXP_STATUS)
                {
                    int i = buf.getInt();
                    throwStatusError(buf, i);
                }

                byte[] handle = buf.getString();         // handle

                while (true)
                {
                    sendREADDIR(handle);

                    header = MakeHeader(buf, header);
                    length = header.Length;
                    type = header.type;
                    if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME)
                    {
                        throw new SftpException(SSH_FX_FAILURE, "");
                    }
                    if (type == SSH_FXP_STATUS)
                    {
                        fill(buf, length);
                        int i = buf.getInt();
                        if (i == SSH_FX_EOF)
                            break;
                        throwStatusError(buf, i);
                    }

                    buf.rewind();
                    fill(buf.buffer, 0, 4); length -= 4;
                    int count = buf.getInt();

                    //byte[] str;
                    //int flags;

                    buf.reset();
                    while (count > 0)
                    {
                        if (length > 0)
                        {
                            buf.shift();
                            int j = (buf.buffer.Length > (buf.index + length)) ?
                              length :
                              (buf.buffer.Length - buf.index);
                            int i = fill(buf.buffer, buf.index, j);
                            buf.index += i;
                            length -= i;
                        }
                        byte[] filename = buf.getString();
                        byte[] longname = null;
                        if (server_version <= 3)
                        {
                            longname = buf.getString();
                        }
                        SftpATTRS attrs = SftpATTRS.getATTR(buf);

                        bool find = false;
                        string f = null;
                        if (pattern == null)
                        {
                            find = true;
                        }
                        else if (!pattern_has_wildcard)
                        {
                            find = Util.array_equals(pattern, filename);
                        }
                        else
                        {
                            byte[] _filename = filename;
                            if (!fEncoding_is_utf8)
                            {
                                f = Util.byte2str(_filename, fEncoding);
                                _filename = Util.str2byte(f, UTF8);
                            }
                            find = Util.glob(pattern, _filename);
                        }

                        if (find)
                        {
                            if (f == null)
                            {
                                f = Util.byte2str(filename, fEncoding);
                            }
                            string l = null;
                            if (longname == null)
                            {
                                // TODO: we need to generate long name from attrs
                                //       for the sftp protocol 4(and later).
                                l = attrs.ToString() + " " + f;
                            }
                            else
                            {
                                l = Util.byte2str(longname, fEncoding);
                            }
                            v.Add(new LsEntry(f, l, attrs));
                        }

                        count--;
                    }
                }
                _sendCLOSE(handle, header);

                /*
                if(v.Count==1 && pattern_has_wildcard){
                  LsEntry le=(LsEntry)v.elementAt(0);
                  if(le.getAttrs().isDir()){
                    string f=le.getFilename();
                    if(isPattern(f)){
                      f=Util.quote(f);
                    }
                    if(!dir.EndsWith("/")){
                      dir+="/";
                    }
                    v=null;
                    return ls(dir+f);
                  }
                }
                */

                return v;
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }
        public string readlink(string path)
        {
            try
            {

                if (server_version < 3)
                {
                    throw new SftpException(SSH_FX_OP_UNSUPPORTED,
                                            "The remote sshd is too old to support symlink operation.");
                }

                path = remoteAbsolutePath(path);

                path = isUnique(path);

                sendREADLINK(Util.str2byte(path, fEncoding));

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                if (type == SSH_FXP_NAME)
                {
                    int count = buf.getInt();       // count
                    byte[] filename = null;
                    for (int i = 0; i < count; i++)
                    {
                        filename = buf.getString();
                        if (server_version <= 3)
                        {
                            byte[] longname = buf.getString();
                        }
                        SftpATTRS.getATTR(buf);
                    }
                    return Util.byte2str(filename, fEncoding);
                }

                int ii = buf.getInt();
                throwStatusError(buf, ii);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
            return null;
        }
        public void symlink(string oldpath, string newpath)
        {
            if (server_version < 3)
            {
                throw new SftpException(SSH_FX_OP_UNSUPPORTED,
                                        "The remote sshd is too old to support symlink operation.");
            }

            try
            {
                oldpath = remoteAbsolutePath(oldpath);
                newpath = remoteAbsolutePath(newpath);

                oldpath = isUnique(oldpath);

                if (isPattern(newpath))
                {
                    throw new SftpException(SSH_FX_FAILURE, newpath);
                }
                newpath = Util.unquote(newpath);

                sendSYMLINK(Util.str2byte(oldpath, fEncoding),
                            Util.str2byte(newpath, fEncoding));

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }

                int i = buf.getInt();
                if (i == SSH_FX_OK) return;
                throwStatusError(buf, i);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void rename(string oldpath, string newpath)
        {
            if (server_version < 2)
            {
                throw new SftpException(SSH_FX_OP_UNSUPPORTED,
                                        "The remote sshd is too old to support rename operation.");
            }

            try
            {
                oldpath = remoteAbsolutePath(oldpath);
                newpath = remoteAbsolutePath(newpath);

                oldpath = isUnique(oldpath);

                List<string> v = glob_remote(newpath);
                int vsize = v.Count;
                if (vsize >= 2)
                {
                    throw new SftpException(SSH_FX_FAILURE, v.ToString());
                }
                if (vsize == 1)
                {
                    newpath = v[0];
                }
                else
                {  // vsize==0
                    if (isPattern(newpath))
                        throw new SftpException(SSH_FX_FAILURE, newpath);
                    newpath = Util.unquote(newpath);
                }

                sendRENAME(Util.str2byte(oldpath, fEncoding),
                           Util.str2byte(newpath, fEncoding));

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }

                int i = buf.getInt();
                if (i == SSH_FX_OK) return;
                throwStatusError(buf, i);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }
        public void rm(string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;

                Header header = new Header();

                for (int j = 0; j < vsize; j++)
                {
                    path = v[j];
                    sendREMOVE(Util.str2byte(path, fEncoding));

                    header = MakeHeader(buf, header);
                    int length = header.Length;
                    int type = header.type;

                    fill(buf, length);

                    if (type != SSH_FXP_STATUS)
                    {
                        throw new SftpException(SSH_FX_FAILURE, "");
                    }
                    int i = buf.getInt();
                    if (i != SSH_FX_OK)
                    {
                        throwStatusError(buf, i);
                    }
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        private bool isRemoteDir(string path)
        {
            try
            {
                sendSTAT(Util.str2byte(path, fEncoding));

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_ATTRS)
                {
                    return false;
                }
                SftpATTRS attr = SftpATTRS.getATTR(buf);
                return attr.isDir();
            }
            catch /*(Exception e)*/ { }
            return false;
        }

        public void chgrp(int gid, string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;
                for (int j = 0; j < vsize; j++)
                {
                    path = v[j];

                    SftpATTRS attr = _stat(path);

                    attr.setFLAGS(0);
                    attr.setUIDGID(attr.uid, gid);
                    _setStat(path, attr);
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void chown(int uid, string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;
                for (int j = 0; j < vsize; j++)
                {
                    path = v[j];

                    SftpATTRS attr = _stat(path);

                    attr.setFLAGS(0);
                    attr.setUIDGID(uid, attr.gid);
                    _setStat(path, attr);
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void chmod(int permissions, string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;
                for (int j = 0; j < vsize; j++)
                {
                    path = v[j];

                    SftpATTRS attr = _stat(path);

                    attr.setFLAGS(0);
                    attr.setPERMISSIONS(permissions);
                    _setStat(path, attr);
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void setMtime(string path, int mtime)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;
                for (int j = 0; j < vsize; j++)
                {
                    path = v[j];

                    SftpATTRS attr = _stat(path);

                    attr.setFLAGS(0);
                    attr.setACMODTIME(attr.getATime(), mtime);
                    _setStat(path, attr);
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void rmdir(string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;

                Header header = new Header();

                for (int j = 0; j < vsize; j++)
                {
                    path = v[j];
                    sendRMDIR(Util.str2byte(path, fEncoding));

                    header = MakeHeader(buf, header);
                    int length = header.Length;
                    int type = header.type;

                    fill(buf, length);

                    if (type != SSH_FXP_STATUS)
                    {
                        throw new SftpException(SSH_FX_FAILURE, "");
                    }

                    int i = buf.getInt();
                    if (i != SSH_FX_OK)
                    {
                        throwStatusError(buf, i);
                    }
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public void mkdir(string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                sendMKDIR(Util.str2byte(path, fEncoding), null);

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }

                int i = buf.getInt();
                if (i == SSH_FX_OK) return;
                throwStatusError(buf, i);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public SftpATTRS stat(string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                path = isUnique(path);

                return _stat(path);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
            //return null;
        }

        private SftpATTRS _stat(byte[] path)
        {
            try
            {

                sendSTAT(path);

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_ATTRS)
                {
                    if (type == SSH_FXP_STATUS)
                    {
                        int i = buf.getInt();
                        throwStatusError(buf, i);
                    }
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                SftpATTRS attr = SftpATTRS.getATTR(buf);
                return attr;
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
            //return null;
        }

        private SftpATTRS _stat(string path)
        {
            return _stat(Util.str2byte(path, fEncoding));
        }

        public SftpATTRS lstat(string path)
        {
            try
            {
                path = remoteAbsolutePath(path);

                path = isUnique(path);

                return _lstat(path);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        private SftpATTRS _lstat(string path)
        {
            try
            {
                sendLSTAT(Util.str2byte(path, fEncoding));

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_ATTRS)
                {
                    if (type == SSH_FXP_STATUS)
                    {
                        int i = buf.getInt();
                        throwStatusError(buf, i);
                    }
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                SftpATTRS attr = SftpATTRS.getATTR(buf);
                return attr;
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        private byte[] _realpath(string path)
        {
            sendREALPATH(Util.str2byte(path, fEncoding));

            Header header = new Header();
            header = MakeHeader(buf, header);
            int length = header.Length;
            int type = header.type;

            fill(buf, length);

            if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME)
            {
                throw new SftpException(SSH_FX_FAILURE, "");
            }
            int i;
            if (type == SSH_FXP_STATUS)
            {
                i = buf.getInt();
                throwStatusError(buf, i);
            }
            i = buf.getInt();   // count

            byte[] str = null;
            while (i-- > 0)
            {
                str = buf.getString();  // absolute path;
                if (server_version <= 3)
                {
                    byte[] lname = buf.getString();  // long filename
                }
                SftpATTRS attr = SftpATTRS.getATTR(buf);  // dummy attribute
            }
            return str;
        }

        public void setStat(string path, SftpATTRS attr)
        {
            try
            {
                path = remoteAbsolutePath(path);

                List<string> v = glob_remote(path);
                int vsize = v.Count;
                for (int j = 0; j < vsize; j++)
                {
                    path = (string)(v[j]);
                    _setStat(path, attr);
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }
        private void _setStat(string path, SftpATTRS attr)
        {
            try
            {
                sendSETSTAT(Util.str2byte(path, fEncoding), attr);

                Header header = new Header();
                header = MakeHeader(buf, header);
                int length = header.Length;
                int type = header.type;

                fill(buf, length);

                if (type != SSH_FXP_STATUS)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                int i = buf.getInt();
                if (i != SSH_FX_OK)
                {
                    throwStatusError(buf, i);
                }
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public string Pwd { get { return getCwd(); } }
        public string Lpwd { get { return lcwd; } }
        public string Version { get { return version; } }
        public string getHome()
        {
            if (home == null)
            {
                try
                {
                    byte[] _home = _realpath("");
                    home = Util.byte2str(_home, fEncoding);
                }
                catch (Exception e)
                {
                    if (e is SftpException) throw (SftpException)e;
                    throw new SftpException(SSH_FX_FAILURE, "",e);
                }
            }
            return home;
        }

        private string getCwd()
        {
            if (cwd == null)
                cwd = getHome();
            return cwd;
        }

        private void setCwd(string cwd)
        {
            this.cwd = cwd;
        }

        private void read(byte[] buf, int s, int l)
        {
            int i = 0;
            while (l > 0)
            {
                i = io_in.Read(buf, s, l);
                if (i <= 0)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                s += i;
                l -= i;
            }
        }

        private bool checkStatus(int[] ackid, Header header)
        {
            header = MakeHeader(buf, header);
            int length = header.Length;
            int type = header.type;
            if (ackid != null)
                ackid[0] = header.rid;

            fill(buf, length);

            if (type != SSH_FXP_STATUS)
            {
                throw new SftpException(SSH_FX_FAILURE, "");
            }
            int i = buf.getInt();
            if (i != SSH_FX_OK)
            {
                throwStatusError(buf, i);
            }
            return true;
        }
        private bool _sendCLOSE(byte[] handle, Header header)
        {
            sendCLOSE(handle);
            return checkStatus(null, header);
        }

        private void sendINIT()
        {
            packet.reset();
            putHEAD(SSH_FXP_INIT, 5);
            buf.putInt(3);                // version 3
            getSession().write(packet, this, 5 + 4);
        }

        private void sendREALPATH(byte[] path)
        {
            sendPacketPath(SSH_FXP_REALPATH, path);
        }
        private void sendSTAT(byte[] path)
        {
            sendPacketPath(SSH_FXP_STAT, path);
        }
        private void sendLSTAT(byte[] path)
        {
            sendPacketPath(SSH_FXP_LSTAT, path);
        }
        private void sendFSTAT(byte[] handle)
        {
            sendPacketPath(SSH_FXP_FSTAT, handle);
        }
        private void sendSETSTAT(byte[] path, SftpATTRS attr)
        {
            packet.reset();
            putHEAD(SSH_FXP_SETSTAT, 9 + path.Length + attr.length());
            buf.putInt(seq++);
            buf.putString(path);             // path
            attr.dump(buf);
            getSession().write(packet, this, 9 + path.Length + attr.length() + 4);
        }
        private void sendREMOVE(byte[] path)
        {
            sendPacketPath(SSH_FXP_REMOVE, path);
        }
        private void sendMKDIR(byte[] path, SftpATTRS attr)
        {
            packet.reset();
            putHEAD(SSH_FXP_MKDIR, 9 + path.Length + (attr != null ? attr.length() : 4));
            buf.putInt(seq++);
            buf.putString(path);             // path
            if (attr != null) attr.dump(buf);
            else buf.putInt(0);
            getSession().write(packet, this, 9 + path.Length + (attr != null ? attr.length() : 4) + 4);
        }
        private void sendRMDIR(byte[] path)
        {
            sendPacketPath(SSH_FXP_RMDIR, path);
        }
        private void sendSYMLINK(byte[] p1, byte[] p2)
        {
            sendPacketPath(SSH_FXP_SYMLINK, p1, p2);
        }
        private void sendREADLINK(byte[] path)
        {
            sendPacketPath(SSH_FXP_READLINK, path);
        }
        private void sendOPENDIR(byte[] path)
        {
            sendPacketPath(SSH_FXP_OPENDIR, path);
        }
        private void sendREADDIR(byte[] path)
        {
            sendPacketPath(SSH_FXP_READDIR, path);
        }
        private void sendRENAME(byte[] p1, byte[] p2)
        {
            sendPacketPath(SSH_FXP_RENAME, p1, p2);
        }
        private void sendCLOSE(byte[] path)
        {
            sendPacketPath(SSH_FXP_CLOSE, path);
        }
        private void sendOPENR(byte[] path)
        {
            sendOPEN(path, SSH_FXF_READ);
        }
        private void sendOPENW(byte[] path)
        {
            sendOPEN(path, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC);
        }
        private void sendOPENA(byte[] path)
        {
            sendOPEN(path, SSH_FXF_WRITE |/*SSH_FXF_APPEND|*/SSH_FXF_CREAT);
        }
        private void sendOPEN(byte[] path, int mode)
        {
            packet.reset();
            putHEAD(SSH_FXP_OPEN, 17 + path.Length);
            buf.putInt(seq++);
            buf.putString(path);
            buf.putInt(mode);
            buf.putInt(0);           // attrs
            getSession().write(packet, this, 17 + path.Length + 4);
        }
        private void sendPacketPath(byte fxp, byte[] path)
        {
            packet.reset();
            putHEAD(fxp, 9 + path.Length);
            buf.putInt(seq++);
            buf.putString(path);             // path
            getSession().write(packet, this, 9 + path.Length + 4);
        }
        private void sendPacketPath(byte fxp, byte[] p1, byte[] p2)
        {
            packet.reset();
            putHEAD(fxp, 13 + p1.Length + p2.Length);
            buf.putInt(seq++);
            buf.putString(p1);
            buf.putString(p2);
            getSession().write(packet, this, 13 + p1.Length + p2.Length + 4);
        }

        private int sendWRITE(byte[] handle, long offset,
                              byte[] data, int start, int length)
        {
            int _length = length;
            packet.reset();
            if (buf.buffer.Length < buf.index + 13 + 21 + handle.Length + length
               + 32 + 20  // padding and mac
        )
            {
                _length = buf.buffer.Length - (buf.index + 13 + 21 + handle.Length
                                           + 32 + 20  // padding and mac
          );
                //Console.Error.WriteLine("_length="+_length+" length="+length);
            }

            putHEAD(SSH_FXP_WRITE, 21 + handle.Length + _length);       // 14
            buf.putInt(seq++);                                      //  4
            buf.putString(handle);                                  //  4+handle.Length
            buf.putLong(offset);                                    //  8
            if (buf.buffer != data)
            {
                buf.putString(data, start, _length);                    //  4+_length
            }
            else
            {
                buf.putInt(_length);
                buf.skip(_length);
            }
            getSession().write(packet, this, 21 + handle.Length + _length + 4);
            return _length;
        }

        private void sendREAD(byte[] handle, long offset, int length)
        {
            packet.reset();
            putHEAD(SSH_FXP_READ, 21 + handle.Length);
            buf.putInt(seq++);
            buf.putString(handle);
            buf.putLong(offset);
            buf.putInt(length);
            getSession().write(packet, this, 21 + handle.Length + 4);
        }

        private void putHEAD(byte type, int length)
        {
            buf.putByte((byte)Session.SSH_MSG_CHANNEL_DATA);
            buf.putInt(recipient);
            buf.putInt(length + 4);
            buf.putInt(length);
            buf.putByte(type);
        }

        private List<string> glob_remote(string _path)
        {
            List<string> v = new List<string>();
            
            int i = 0;

            int foo = _path.LastIndexOf('/');
            if (foo < 0)
            {  // it is not absolute path.
                v.Add(Util.unquote(_path));
                return v;
            }

            string dir = _path.Substring(0, ((foo == 0) ? 1 : foo));
            string _pattern = _path.Substring(foo + 1);

            dir = Util.unquote(dir);

            byte[] pattern = null;
            byte[][] _pattern_utf8 = new byte[1][];
            bool pattern_has_wildcard = isPattern(_pattern, _pattern_utf8);

            if (!pattern_has_wildcard)
            {
                if (dir.Length != 1) // not equal to "/"
                    dir += "/";
                v.Add(dir + Util.unquote(_pattern));
                return v;
            }

            pattern = _pattern_utf8[0];

            sendOPENDIR(Util.str2byte(dir, fEncoding));

            Header header = new Header();
            header = MakeHeader(buf, header);
            int length = header.Length;
            int type = header.type;

            fill(buf, length);

            if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE)
            {
                throw new SftpException(SSH_FX_FAILURE, "");
            }
            if (type == SSH_FXP_STATUS)
            {
                i = buf.getInt();
                throwStatusError(buf, i);
            }

            byte[] handle = buf.getString();         // filename
            string pdir = null;                      // parent directory

            while (true)
            {
                sendREADDIR(handle);
                header = MakeHeader(buf, header);
                length = header.Length;
                type = header.type;

                if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME)
                {
                    throw new SftpException(SSH_FX_FAILURE, "");
                }
                if (type == SSH_FXP_STATUS)
                {
                    fill(buf, length);
                    break;
                }

                buf.rewind();
                fill(buf.buffer, 0, 4); length -= 4;
                int count = buf.getInt();

                byte[] str;
                //int flags;

                buf.reset();
                while (count > 0)
                {
                    if (length > 0)
                    {
                        buf.shift();
                        int j = (buf.buffer.Length > (buf.index + length)) ? length : (buf.buffer.Length - buf.index);
                        i = io_in.Read(buf.buffer, buf.index, j);
                        if (i <= 0) break;
                        buf.index += i;
                        length -= i;
                    }

                    byte[] filename = buf.getString();
                    //Console.Error.WriteLine("filename: "+Encoding.UTF8.GetString(filename));
                    if (server_version <= 3)
                    {
                        str = buf.getString();  // longname
                    }
                    SftpATTRS attrs = SftpATTRS.getATTR(buf);

                    byte[] _filename = filename;
                    string f = null;
                    bool found = false;

                    if (!fEncoding_is_utf8)
                    {
                        f = Util.byte2str(filename, fEncoding);
                        _filename = Util.str2byte(f, UTF8);
                    }
                    found = Util.glob(pattern, _filename);

                    if (found)
                    {
                        if (f == null)
                        {
                            f = Util.byte2str(filename, fEncoding);
                        }
                        if (pdir == null)
                        {
                            pdir = dir;
                            if (!pdir.EndsWith("/"))
                            {
                                pdir += "/";
                            }
                        }
                        v.Add(pdir + f);
                    }
                    count--;
                }
            }
            if (_sendCLOSE(handle, header))
                return v;
            return null;
        }

        private bool isPattern(byte[] path)
        {
            int i = path.Length - 1;
            while (i >= 0)
            {
                if (path[i] == '*' || path[i] == '?')
                {
                    if (i > 0 && path[i - 1] == '\\')
                    {
                        i--;
                        if (i > 0 && path[i - 1] == '\\')
                        {    // \\* or \\?
                            break;
                        }
                    }
                    else
                    {
                        break;
                    }
                }
                i--;
            }
            // Console.Error.WriteLine("isPattern: ["+(Encoding.UTF8.GetString(path))+"] "+(!(i<0)));
            return !(i < 0);
        }

        private List<string> glob_local(string _path)
        {
            //Console.Error.WriteLine("glob_local: "+_path);
            List<string> v = new List<string>();
            //Vector v = new Vector();
            byte[] path = Util.str2byte(_path, UTF8);
            int i = path.Length - 1;
            while (i >= 0)
            {
                if (path[i] != '*' && path[i] != '?')
                {
                    i--;
                    continue;
                }
                if (!fs_is_bs &&
                   i > 0 && path[i - 1] == '\\')
                {
                    i--;
                    if (i > 0 && path[i - 1] == '\\')
                    {
                        i--;
                        i--;
                        continue;
                    }
                }
                break;
            }

            if (i < 0) { v.Add(fs_is_bs ? _path : Util.unquote(_path)); return v; }

            while (i >= 0)
            {
                if (path[i] == file_separatorc ||
                   (fs_is_bs && path[i] == '/'))
                { // On Windows, '/' is also the separator.
                    break;
                }
                i--;
            }

            if (i < 0) { v.Add(fs_is_bs ? _path : Util.unquote(_path)); return v; }

            byte[] dir;
            if (i == 0) { dir = new byte[] { (byte)file_separatorc }; }
            else
            {
                dir = new byte[i];
                Array.Copy(path, 0, dir, 0, i);
            }

            byte[] pattern = new byte[path.Length - i - 1];
            Array.Copy(path, i + 1, pattern, 0, pattern.Length);

            //Console.Error.WriteLine("dir: "+Encoding.UTF8.GetString(dir)+" pattern: "+Encoding.UTF8.GetString(pattern));
            try
            {
                string[] children = Directory.GetFileSystemEntries(Util.byte2str(dir, UTF8));
                string pdir = Util.byte2str(dir) + file_separator;
                for (int j = 0; j < children.Length; j++)
                {
                    //Console.Error.WriteLine("children: "+children[j]);
                    if (Util.glob(pattern, Util.str2byte(children[j], UTF8)))
                    {
                        v.Add(pdir + children[j]);
                    }
                }
            }
            catch //(Exception e)
            {
            }
            return v;
        }

        private void throwStatusError(Buffer buf, int i)
        {
            if (server_version >= 3 &&   // WindRiver's sftp will send invalid 
               buf.getLength() >= 4)
            {   // SSH_FXP_STATUS packet.
                byte[] str = buf.getString();
                //byte[] tag=buf.getString();
                throw new SftpException(i, Util.byte2str(str, UTF8));
            }
            else
            {
                throw new SftpException(i, "Failure");
            }
        }

        private static bool isLocalAbsolutePath(string path)
        {
            return Path.IsPathRooted(path);
        }


        public override void disconnect()
        {
            base.disconnect();
        }

        private bool isPattern(string path, byte[][] utf8)
        {
            byte[] _path = Util.str2byte(path, UTF8);
            if (utf8 != null)
                utf8[0] = _path;
            return isPattern(_path);
        }

        private bool isPattern(string path)
        {
            return isPattern(path, null);
        }

        private void fill(Buffer buf, int len)
        {
            buf.reset();
            fill(buf.buffer, 0, len);
            buf.skip(len);
        }

        private int fill(byte[] buf, int s, int len)
        {
            int i = 0;
            int foo = s;
            while (len > 0)
            {
                i = io_in.Read(buf, s, len);
                if (i <= 0)
                {
                    throw new IOException("inputstream is closed");
                    //return (s-foo)==0 ? i : s-foo;
                }
                s += i;
                len -= i;
            }
            return s - foo;
        }
        private void skip(long foo)
        {
            while (foo > 0)
            {
                long bar = io_in.Seek(foo,SeekOrigin.Current);
                if (bar <= 0)
                    break;
                foo -= bar;
            }
        }

        class Header
        {
            internal int Length;
            internal int type;
            internal int rid;
        }
        private Header MakeHeader(Buffer buf, Header header)
        {
            buf.rewind();
            int i = fill(buf.buffer, 0, 9);
            header.Length = buf.getInt() - 5;
            header.type = buf.getByte() & 0xff;
            header.rid = buf.getInt();
            return header;
        }

        private string remoteAbsolutePath(string path)
        {
            if (path[0] == '/') return path;
            string cwd = getCwd();
            if (cwd.EndsWith("/")) return cwd + path;
            return cwd + "/" + path;
        }

        private string localAbsolutePath(string path)
        {
            if (isLocalAbsolutePath(path)) return path;
            if (lcwd.EndsWith(file_separator)) return lcwd + path;
            return lcwd + file_separator + path;
        }

        /**
         * This method will check if the given string can be expanded to the
         * unique string.  If it can be expanded to mutiple files, SftpException
         * will be thrown.
         * @return the returned string is unquoted.
         */
        private string isUnique(string path)
        {
            List<string> v = glob_remote(path);
            if (v.Count != 1)
            {
                throw new SftpException(SSH_FX_FAILURE, path + " is not unique: " + v.ToString());
            }
            return v[0];
        }

        public int getServerVersion()
        {
            if (!isConnected())
            {
                throw new SftpException(SSH_FX_FAILURE, "The channel is not connected.");
            }
            return server_version;
        }

        public void setFilenameEncoding(string encoding)
        {
            int sversion = getServerVersion();
            if (sversion > 3 &&
               !encoding.Equals(UTF8))
            {
                throw new SftpException(SSH_FX_FAILURE,
                                        "The encoding can not be changed for this sftp server.");
            }
            if (encoding.Equals(UTF8))
            {
                encoding = UTF8;
            }
            fEncoding = encoding;
            fEncoding_is_utf8 = fEncoding.Equals(UTF8);
        }

        public string getExtension(string key)
        {
            if (extensions == null)
                return null;
            return (string)extensions[key];
        }

        public string realpath(string path)
        {
            try
            {
                byte[] _path = _realpath(remoteAbsolutePath(path));
                return Util.byte2str(_path, fEncoding);
            }
            catch (Exception e)
            {
                if (e is SftpException) throw (SftpException)e;
                throw new SftpException(SSH_FX_FAILURE, "",e);
            }
        }

        public class LsEntry : IComparable<LsEntry>
        {
            private string filename;
            private string longname;
            private SftpATTRS attrs;
            internal LsEntry(string filename, string longname, SftpATTRS attrs)
            {
                setFilename(filename);
                setLongname(longname);
                setAttrs(attrs);
            }
            public string getFilename() { return filename; }
            void setFilename(string filename) { this.filename = filename; }
            public string getLongname() { return longname; }
            void setLongname(string longname) { this.longname = longname; }
            public SftpATTRS getAttrs() { return attrs; }
            void setAttrs(SftpATTRS attrs) { this.attrs = attrs; }
            public override string ToString() { return longname; }

            public int compareTo(Object o)
            {
                if (o is LsEntry)
                {
                    return filename.CompareTo(((LsEntry)o).getFilename());
                }
                throw new InvalidCastException("a decendent of LsEntry must be given.");
            }

            #region IComparable<LsEntry> Members

            public int CompareTo(LsEntry other)
            {
                return filename.CompareTo(other.getFilename());
            }

            #endregion
        }
    }
}
