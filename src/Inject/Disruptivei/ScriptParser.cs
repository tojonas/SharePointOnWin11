

namespace Disruptivei
{
    using Disruptive.Core;
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;

    public class ScriptParser
    {
        static void T(string s) => Debug.WriteLine(s);

        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine,
        out int pNumArgs);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        List<string> ParseCommandLine(string commandLine)
        {
            var argv = CommandLineToArgvW(commandLine, out var numArgs);
            if (argv == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
            try
            {
                var args = new List<string>();
                for (int i = 0; i < numArgs; i++)
                {
                    var argPtr = Marshal.ReadIntPtr(argv, i * IntPtr.Size);
                    args.Add(Marshal.PtrToStringUni(argPtr));
                }
                return args;
            }
            finally
            {
                LocalFree(argv);
            }
        }
        //
        // Parses a command line to see if it is enabling IIS
        // @"C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe"" -ExecutionPolicy Bypass ""C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1 -logFile C:\Users\xxx\AppData\Local\Temp\Pre7398.tmp.PS1.log";
        //
        public (bool match, string cmd) ProbeScript(string commandLine, bool rewrite=false)
        {
            const string logFileToken = " -logFile ";
            
            // Check if powershell.exe is invoked
            if (commandLine.IndexOf("powershell.exe", StringComparison.OrdinalIgnoreCase) == -1)
            {
                T("This is not a PowerShell command.");
                return (false,commandLine);
            }
            var args = ParseCommandLine(commandLine);
            if (args.Count == 0)
            {
                T("No arguments found in command line.");
                return (false, commandLine);
            }
            var bypassIndex = args.FindIndex(arg => arg.Equals("Bypass", StringComparison.OrdinalIgnoreCase));
            if (bypassIndex == -1)
            {
                T("ExecutionPolicy Bypass not found in command line.");
                return (false, commandLine);
            }
            if (bypassIndex != args.Count - 2)
            {
                T("ExecutionPolicy Bypass should be the last argument in the command line before scripts.");
                return (false, commandLine);
            }
            var input = args[args.Count - 1];
            // Split on -logFile
            var logFileIndex = input.IndexOf(logFileToken, StringComparison.OrdinalIgnoreCase);
            if (logFileIndex == -1)
            {
                T($"Could not find {logFileToken} in input.");
                return (false, commandLine);
            }

            var scriptPath = input.Substring(0, logFileIndex).Trim();
            var logFilePath = input.Substring(logFileIndex + logFileToken.Length).Trim();

            if (!File.Exists(scriptPath))
            {
                T($"PowerShell script file [{scriptPath}] not found.");
                return (false, commandLine);
            }
            //NET-WCF-Pipe-Activation45
            // Probe the PS1 content
            var scriptContent = File.ReadAllText(scriptPath);
            if (!scriptContent.Contains("NET-HTTP-Activation") && !scriptContent.Contains("NET-WCF-Pipe-Activation45"))
            {
                T("This script does not contain NET-HTTP-Activation.");
                return (false, commandLine);
            }
            
            var resource = scriptContent.Contains("NET-WCF-Pipe-Activation45") ?
                "Powershell.SubscriptionEdition.ps1" :
                "Powershell.EnableIISFeatures.ps1";
            T($"This script appears to be a Windows Server script. using resource: {resource}");
            var cmd = ResourceReader.GetResourceString(resource);

            if (rewrite)
            {
                T($"Rewriting script {scriptPath}");
                File.WriteAllText(scriptPath, cmd);
            }
            return (true, cmd);
        }


    }
}
