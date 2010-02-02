using System;

namespace SharpSSH.NG
{
    abstract class Logger
    {
        public const int DEBUG = 0;
        public const int INFO = 1;
        public const int WARN = 2;
        public const int ERROR = 3;
        public const int FATAL = 4;

        public abstract bool isEnabled(int level);

        public abstract void log(int level, string message);

        /*
        public readonly Logger SIMPLE_LOGGER=new Logger(){
            public bool isEnabled(int level){return true;}
            public void log(int level, string message){Console.Error.WriteLine(message);}
          };
        readonly Logger DEVNULL=new Logger(){
            public bool isEnabled(int level){return false;}
            public void log(int level, string message){}
          };
        */
    }
}
