using System;

namespace ServerManagerCmd
{
    class Program
    {
        static int Main(string[] args)
        {
            T("ServerManagerCmd " + String.Join(",", args));

            if (args[0] == "-powershell")
            {
                //T("Setting exit code to 3010");
                //return 3010;
            }
            return 0;
        }

        static void T(string fmt, params object[] args)
        {
            System.Diagnostics.Trace.WriteLine(string.Format(fmt, args));
        }
    }
}
