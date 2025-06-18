namespace Disruptivei.Launcher
{
    using Disruptivei.Inject;
    using EasyHook;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Runtime.Remoting;
    using System.Security.Principal;
    using System.Threading;
    using System.Windows.Forms;

    //https://github.com/Reloaded-Project/Reloaded.Hooks
    //M692G-8N2JP-GG8B2-2W2P7-YY7J6
    internal class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            var currDir = Directory.GetCurrentDirectory();
            try
            {
                string channelName = null;
                RemoteHooking.IpcCreateServer<CallbackInterface>(ref channelName, WellKnownObjectMode.Singleton, new WellKnownSidType[0]);

                string fileName;
                using (OpenFileDialog dialog = new OpenFileDialog())
                {
                    do
                    {
                        dialog.Filter = "Executable Files (.exe)|*.exe";
                        dialog.FilterIndex = 1;
                        if (dialog.ShowDialog() != DialogResult.OK)
                        {
                            Console.WriteLine("Cancelling...");
                            return -1;
                        }
                        fileName = dialog.FileName;
                    }
                    while (!File.Exists(fileName));
                }

                Console.Write(fileName);

                string serverManagerCmdFake = null;
                var prerequisiteInstaller = fileName.ToLower().Contains("prerequisiteinstaller");
                if (prerequisiteInstaller)
                {
                    string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "ServerManagerCmd.exe");
                    if (!File.Exists(path))
                    {
                        var localPath = Path.Combine(currDir, "ServerManagerCmd.exe");
                        if (File.Exists(localPath))
                        {
                            File.Copy(localPath, path);
                            serverManagerCmdFake = path;
                        }
                    }
                }

                NativeMethods.STARTUPINFO lpStartupInfo = new NativeMethods.STARTUPINFO();
                NativeMethods.PROCESS_INFORMATION lpProcessInformation = new NativeMethods.PROCESS_INFORMATION();
                try
                {
                    var workingDirectory = Path.GetDirectoryName(fileName);
                    var created = NativeMethods.CreateProcess(
                        fileName,
                        null,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        false,
                        NativeMethods.ProcessCreationFlags.CREATE_SUSPENDED,
                        IntPtr.Zero,
                        workingDirectory,
                        ref lpStartupInfo,
                        out lpProcessInformation
                        );

                    if (created)
                    {
                        var targetPid = (int)lpProcessInformation.dwProcessId;
                        Console.Write($" PID: {targetPid}");

                        var injectDll = Path.Combine(currDir, "Inject.dll");
                        RemoteHooking.Inject(targetPid, injectDll, injectDll, channelName, !prerequisiteInstaller);
                        Thread.Sleep(1000);
                        NativeMethods.ResumeThread(lpProcessInformation.hThread);

                        uint waitResult = NativeMethods.WaitForSingleObject(lpProcessInformation.hProcess, uint.MaxValue);
                        if (waitResult != 0)
                        {
                            Console.WriteLine($"WaitForSingleObject failed or was signaled abnormally:{waitResult}");
                        }
                        if (!NativeMethods.GetExitCodeProcess(lpProcessInformation.hProcess, out var exitCode))
                        {
                            Console.WriteLine("Executed command but couldn't get exit code.");
                        }
                        else
                        {
                            Console.WriteLine($"Exit code process: {exitCode:X}");
                        }
                    }
                    else
                    {
                        Console.WriteLine($"CreateProcess {fileName} failed: {Marshal.GetLastWin32Error()}");
                    }
                }
                finally
                {
                    NativeMethods.CloseHandle(lpProcessInformation.hProcess);
                    NativeMethods.CloseHandle(lpProcessInformation.hThread);
                    if (serverManagerCmdFake != null)
                    {
                        File.Delete(serverManagerCmdFake);
                        Console.WriteLine($"Cleaned up {serverManagerCmdFake}");
                    }
                }
            }
            catch (Exception exception2)
            {
                Console.WriteLine($"There was an error while connecting to target:\n{exception2}");
                Console.ReadLine();
            }
            return 0;
        }

        [Flags]
        private enum SuiteMask : ushort
        {
            VER_SUITE_BACKOFFICE = 4,
            VER_SUITE_BLADE = 0x400,
            VER_SUITE_COMPUTE_SERVER = 0x4000,
            VER_SUITE_DATACENTER = 0x80,
            VER_SUITE_EMBEDDEDNT = 0x40,
            VER_SUITE_ENTERPRISE = 2,
            VER_SUITE_PERSONAL = 0x200,
            VER_SUITE_SINGLEUSERTS = 0x100,
            VER_SUITE_SMALLBUSINESS = 1,
            VER_SUITE_SMALLBUSINESS_RESTRICTED = 0x20,
            VER_SUITE_STORAGE_SERVER = 0x2000,
            VER_SUITE_TERMINAL = 0x10,
            VER_SUITE_WH_SERVER = 0x8000
        }
        private enum ProductType : byte
        {
            VER_NT_DOMAIN_CONTROLLER = 2,
            VER_NT_SERVER = 3,
            VER_NT_WORKSTATION = 1
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OSVERSIONINFOEXW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x80)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public SuiteMask wSuiteMask;
            public ProductType wProductType;
            public byte wReserved;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x80)]
            public string szBuffer;
        }

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVersionExW(ref OSVERSIONINFOEXW osvi);

        private static void TestGetVersionInfoEx()
        {
            OSVERSIONINFOEXW osvi = new OSVERSIONINFOEXW();
            osvi.dwOSVersionInfoSize = 284;
            if (true == GetVersionExW(ref osvi))
            {
                T("dwOSVersionInfoSize [{0}]", osvi.dwOSVersionInfoSize);
                T("dwMajorVersion      [{0}]", osvi.dwMajorVersion);
                T("dwMinorVersion      [{0}]", osvi.dwMinorVersion);
                T("dwBuildNumber       [{0}]", osvi.dwBuildNumber);
                T("dwPlatformId        [{0}]", osvi.dwPlatformId);
                T("szCSDVersion        [{0}]", osvi.szCSDVersion);
                T("wServicePackMajor   [{0}]", osvi.wServicePackMajor);
                T("wServicePackMinor   [{0}]", osvi.wServicePackMinor);
                T("wSuiteMask          [{0}]", osvi.wSuiteMask);
                T("wProductType        [{0}]", osvi.wProductType);
                T("wReserved           [{0}]", osvi.wReserved);
            }
            else
            {
                T("GetVersionExW failed sizeof: [{0}] GetLastError [{1}]" + osvi.dwOSVersionInfoSize, Marshal.GetLastWin32Error());
            }
        }
        private static void T(string fmt, params object[] args)
        {
            Trace.WriteLine(string.Format(fmt, args));
        }

        private static void GACRegister()
        {
            TestGetVersionInfoEx();
            try
            {
                // https://easyhook.github.io/api/html/M_EasyHook_Config_Register.htm
                //Config.Register("Fake server OS", "Launcher.exe", "Inject.dll");
            }
            catch (ApplicationException exception)
            {
                Console.WriteLine(exception.ToString());
                MessageBox.Show("This is an administrative task!", "Permission denied...", MessageBoxButtons.OK);
                Process.GetCurrentProcess().Kill();
            }
        }
    }
}

