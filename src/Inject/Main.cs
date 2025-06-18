namespace Disruptivei.Inject
{
    using EasyHook;
    using System;
    using System.Diagnostics;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Threading;

    public class CallbackInterface : MarshalByRefObject
    {
        public void IsInstalled(int pid)
        {
            Console.WriteLine($"\nHook has been installed in target {pid}.\n");
        }
        public void Message(string message)
        {
            var pid = RemoteHooking.GetCurrentProcessId();
            Console.WriteLine($"Message in process {pid} received {message}");
        }
        public void ReportException(Exception ex)
        {
            Console.WriteLine($"\nThe target process has reported an error:\n {ex}");
        }
    }
    static class NativeMethods
    {
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);
    }
    public class Main : IEntryPoint
    {
        private CallbackInterface _callback = null;

        private string _channelName = "Disruptivei.Inject.Main";
        private bool _hookChildren = true;

        private LocalHook CoCreateInstanceHook;
        private LocalHook CreateFileHookA;
        private LocalHook CreateFileHookW;
        private LocalHook CreateProcessAHook;
        private LocalHook CreateProcessAsUserAHook;
        private LocalHook CreateProcessAsUserWHook;
        private LocalHook CreateProcessWHook;
        private LocalHook GetProductInfoHook;
        private LocalHook GetVersionExAHook;
        private LocalHook GetVersionExWHook;
        private LocalHook GetVersionHook;

        private LocalHook LoadLibraryAHook;
        //private LocalHook LoadLibraryExAHook;
        //private LocalHook LoadLibraryExWHook;
        private LocalHook LoadLibraryWHook;
        private LocalHook MessageBoxAHook;
        private LocalHook MessageBoxWHook;
        private LocalHook ShellExecuteWHook;
        private LocalHook VerifyVersionInfoAHook;
        private LocalHook VerifyVersionInfoWHook;
        private LocalHook RegQueryValueExAHook;
        private LocalHook RegQueryValueExWHook;

        //private LocalHook RegOpenKeyExWHook;

        private LocalHook RegGetValueWHook;

        public Main(RemoteHooking.IContext context, string channelName, bool hookChildren)
        {
            _hookChildren = hookChildren;
            _channelName = channelName;

        }
        private void HookProcess(ProcessInfo lpProcessInformation, bool callerSuspended)
        {
            Debug.Assert(lpProcessInformation.ProcessId != 0, "ProcessId should not be zero");
            string processName = Process.GetProcessById(lpProcessInformation.ProcessId).ProcessName;
            if (_hookChildren == false)
            {
                _callback.Message($"Not injecting children {_hookChildren} {processName} {lpProcessInformation.ProcessId}");
                return;
            }
            try
            {
                var assemblyPath = typeof(CallbackInterface).Assembly.Location;
                _callback.Message($"\nInject {processName} {lpProcessInformation.ProcessId} {assemblyPath}.\n");
                RemoteHooking.Inject(lpProcessInformation.ProcessId, assemblyPath, assemblyPath, _channelName, _hookChildren);
                Thread.Sleep(1000);
            }
            catch (Exception ex)
            {
                _callback.Message($"Exception >> {ex}");
            }
        }

        public enum RegistryValueType : int
        {
            Binary = 3,
            DWord = 4,
            ExpandString = 2,
            MultiString = 7,
            [ComVisible(false)]
            None = -1,
            QWord = 11,
            String = 1,
            Unknown = 0
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint RegOpenKeyExW(UIntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, UIntPtr phkResult);
        static uint RegOpenKeyExW_Hooked(UIntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, UIntPtr phkResult)
        {
            uint ret = RegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
            T("RegOpenKeyExW {0}", lpSubKey);
            return ret;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern uint RegGetValueW(IntPtr hKey, string lpSubKey, string lpValue, uint dwFlags, IntPtr pdwType, IntPtr pvData, IntPtr pcbData);
        static uint RegGetValueW_Hooked(IntPtr hKey, string lpSubKey, string lpValue, uint dwFlags, IntPtr pdwType, IntPtr pvData, IntPtr pcbData)
        {
            const string net45ver = "4.5.51209";

            uint ret = RegGetValueW(hKey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
            T("RegGetValueW {0} {1} >> {2}", lpSubKey, lpValue, ret);
            if (pdwType != IntPtr.Zero && pvData != IntPtr.Zero)
            {
                switch ((RegistryValueType)Marshal.ReadInt32(pdwType))
                {
                    case RegistryValueType.String:

                        T("RegGetValueW {0} {1} >> {2} ", lpValue, Marshal.PtrToStringUni(pvData), ret);
                        // This check should take care of all 4.6 versions, Thanks Carlos Roweder Nass
                        if (lpValue == "Version" && System.Runtime.InteropServices.Marshal.PtrToStringUni(pvData).StartsWith("4.6"))
                        {
                            Marshal.Copy(net45ver.ToCharArray(), 0, pvData, net45ver.Length);
                        }
                        else if (lpValue == "Version" && Marshal.PtrToStringUni(pvData) == "4.6.00079")
                        {
                            Marshal.Copy(net45ver.ToCharArray(), 0, pvData, net45ver.Length);
                        }
                        else if (lpValue == "Version" && Marshal.PtrToStringUni(pvData) == "4.6.01038")
                        {
                            Marshal.Copy(net45ver.ToCharArray(), 0, pvData, net45ver.Length);
                        }
                        else if (lpValue == "Version" && Marshal.PtrToStringUni(pvData) == "4.6.01055")
                        {
                            Marshal.Copy(net45ver.ToCharArray(), 0, pvData, net45ver.Length);
                        }
                        break;
                    case RegistryValueType.DWord:
                        T("RegGetValueW {0} {1} >> {2} ", lpValue, Marshal.ReadInt32(pvData), ret);
                        if (lpValue == "Release" && Marshal.ReadInt32(pvData) == 393295)
                        {
                            Marshal.WriteInt32(pvData, 379893);
                        }
                        break;
                    case RegistryValueType.QWord:
                        T("RegGetValueW {0} {1} >> {2} ", lpValue, Marshal.ReadInt64(pvData), ret);
                        break;
                    default:
                        T("RegGetValueW {0} type: {1} >> {2} ", lpValue, (pdwType != IntPtr.Zero) ? Marshal.ReadInt32(pdwType) : 0, ret);
                        break;
                }
            }
            return ret;
        }


        [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern int RegQueryValueExA(IntPtr hKey, [In] string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, ref int lpcbData);
        static int RegQueryValueExA_Hooked(IntPtr hKey, [In] string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, ref int lpcbData)
        {
            int ret = RegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, ref lpcbData);
            try
            {
                if (lpType != IntPtr.Zero && lpData != IntPtr.Zero)
                {
                    switch ((RegistryValueType)Marshal.ReadInt32(lpType))
                    {
                        case RegistryValueType.String:

                            T("RegQueryValueExA {0} {1} >> {2} ", lpValueName, Marshal.PtrToStringAnsi(lpData), ret);
                            if (lpValueName == "Version")//&& Marshal.PtrToStringAnsi(lpData) == "4.6.00079")
                            {

                                //string ver = "4.5.51209";
                                //Marshal.Copy(ver.ToCharArray(), 0, lpData, ver.Length);
                            }
                            break;
                        case RegistryValueType.DWord:
                            T("RegQueryValueExA {0} {1} >> {2} ", lpValueName, Marshal.ReadInt32(lpData), ret);
                            if (lpValueName == "Release")//&& Marshal.ReadInt32(lpData) == 393295)
                            {
                                //Marshal.WriteInt32(lpData, 379893);
                            }
                            break;
                        case RegistryValueType.QWord:
                            T("RegQueryValueExA {0} {1} >> {2} ", lpValueName, Marshal.ReadInt64(lpData), ret);
                            break;
                        default:
                            T("RegQueryValueExA {0} type: {1} >> {2} ", lpValueName, (lpType != IntPtr.Zero) ? Marshal.ReadInt32(lpType) : 0, ret);
                            break;
                    }
                }
                else
                {
                    T("RegQueryValueExA {0} type: {1} >> {2} ", lpValueName, (lpType != IntPtr.Zero) ? Marshal.ReadInt32(lpType) : 0, ret);
                }
            }
            catch (Exception x)
            {
                T("{0}\n\n{1}", lpType, x.ToString());
            }
            return ret;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern int RegQueryValueExW(IntPtr hKey, [In] string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, ref int lpcbData);
        static int RegQueryValueExW_Hooked(IntPtr hKey, [In] string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, ref int lpcbData)
        {
            int ret = RegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, ref lpcbData);
            try
            {
                if (lpType != IntPtr.Zero && lpData != IntPtr.Zero)
                {
                    switch ((RegistryValueType)Marshal.ReadInt32(lpType))
                    {
                        case RegistryValueType.String:

                            T("RegQueryValueExW {0} {1} >> {2} ", lpValueName, Marshal.PtrToStringUni(lpData), ret);
                            if (lpValueName == "Version")//&& Marshal.PtrToStringUni(lpData) == "4.6.00079")
                            {

                                //string ver = "4.5.51209";
                                //Marshal.Copy(ver.ToCharArray(), 0, lpData, ver.Length);
                            }
                            break;
                        case RegistryValueType.DWord:
                            T("RegQueryValueExW {0} {1} >> {2} ", lpValueName, Marshal.ReadInt32(lpData), ret);
                            if (lpValueName == "Release")//&& Marshal.ReadInt32(lpData) == 393295)
                            {
                                //Marshal.WriteInt32(lpData, 379893);
                            }
                            break;
                        case RegistryValueType.QWord:
                            T("RegQueryValueExW {0} {1} >> {2} ", lpValueName, Marshal.ReadInt64(lpData), ret);
                            break;
                        default:
                            T("RegQueryValueExW {0} type: {1} >> {2} ", lpValueName, (lpType != IntPtr.Zero) ? Marshal.ReadInt32(lpType) : 0, ret);
                            break;
                    }
                }
                else
                {
                    T("RegQueryValueExW {0} type: {1} >> {2} ", lpValueName, (lpType != IntPtr.Zero) ? Marshal.ReadInt32(lpType) : 0, ret);
                }
            }
            catch (Exception x)
            {
                T("{0}\n\n{1}", lpType, x.ToString());
            }
            return ret;
        }


        [DllImport("ole32.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern uint CoCreateInstance([In, MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, [In, MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);
        private static uint CoCreateInstance_Hooked([In, MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, [In, MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv)
        {
            string str;
            ProgIDFromCLSID(ref rclsid, out str);
            T("CoCreateInstance {0} [{1}]", rclsid, str);
            return CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, out ppv);
        }

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr CreateFileA(string InFileName, uint InDesiredAccess, uint InShareMode, IntPtr InSecurityAttributes, uint InCreationDisposition, uint InFlagsAndAttributes, IntPtr InTemplateFile);
        private static IntPtr CreateFileA_Hooked(string InFileName, uint InDesiredAccess, uint InShareMode, IntPtr InSecurityAttributes, uint InCreationDisposition, uint InFlagsAndAttributes, IntPtr InTemplateFile)
        {
            T("CreateFileA( {0} )", InFileName);
            return CreateFileA(InFileName, InDesiredAccess, InShareMode, InSecurityAttributes, InCreationDisposition, InFlagsAndAttributes, InTemplateFile);
        }

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string InFileName, uint InDesiredAccess, uint InShareMode, IntPtr InSecurityAttributes, uint InCreationDisposition, uint InFlagsAndAttributes, IntPtr InTemplateFile);
        private static IntPtr CreateFileW_Hooked(string InFileName, uint InDesiredAccess, uint InShareMode, IntPtr InSecurityAttributes, uint InCreationDisposition, uint InFlagsAndAttributes, IntPtr InTemplateFile)
        {
            T("CreateFileW( {0} )", InFileName);
            return CreateFileW(InFileName, InDesiredAccess, InShareMode, InSecurityAttributes, InCreationDisposition, InFlagsAndAttributes, InTemplateFile);
        }

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi)]
        private static extern bool CreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out ProcessInfo lpProcessInformation);
        private bool CreateProcessA_Hooked(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out ProcessInfo lpProcessInformation)
        {
            T("CreateProcessA ({0},{1} ) CREATE_SUSPENDED", lpApplicationName, lpCommandLine);

            // Remember if the original call included CREATE_SUSPENDED
            bool callerSuspended = (dwCreationFlags & ProcessCreationFlags.CREATE_SUSPENDED) != 0;

            dwCreationFlags |= ProcessCreationFlags.CREATE_SUSPENDED;
            bool flag = CreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, (uint)dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, out lpProcessInformation);
            if (lpProcessInformation.ProcessId != 0)
            {
                HookProcess(lpProcessInformation, callerSuspended);
            }
            // Only resume if the caller didn't want the process suspended
            if (!callerSuspended)
            {
                NativeMethods.ResumeThread(lpProcessInformation.hThread);
            }
            T("CreateProcessA ({0},{1}) ResumeThread", lpApplicationName, lpCommandLine);
            return flag;
        }

        [DllImport("Kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode)]
        private static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out ProcessInfo lpProcessInformation);
        private bool CreateProcessW_Hooked(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out ProcessInfo lpProcessInformation)
        {
            T("CreateProcessW ({0},{1}) CREATE_SUSPENDED", lpApplicationName, lpCommandLine);
            // Remember if the original call included CREATE_SUSPENDED
            bool callerSuspended = (dwCreationFlags & ProcessCreationFlags.CREATE_SUSPENDED) != 0;
            dwCreationFlags |= ProcessCreationFlags.CREATE_SUSPENDED;

            if (String.IsNullOrEmpty(lpApplicationName) && lpCommandLine.ToLower().IndexOf("powershell.exe") != -1)
            {
                _callback.Message($"CreateProcessW FOUND powershell.exe replacing commandline {lpCommandLine}");
                lpCommandLine = ReplacePowerShellCmdLine(lpCommandLine);
            }

            bool flag = CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, out lpProcessInformation);
            if (lpProcessInformation.ProcessId != 0)
            {
                HookProcess(lpProcessInformation, callerSuspended);
            }
            // Only resume if the caller didn't want the process suspended
            if (!callerSuspended)
            {
                NativeMethods.ResumeThread(lpProcessInformation.hThread);
            }
            T("CreateProcessW ({0},{1}) ResumeThread", lpApplicationName, lpCommandLine);
            return flag;
        }

        private static string ReplacePowerShellCmdLine(string commandLine)
        {
            var parser = new ScriptParser();
            var result = parser.ProbeScript(commandLine);

            if (!result.match)
            {
                T($"Command line did not match PowerShell script pattern: {commandLine}");
                return commandLine;
            }
            T($"Replacing PowerShell script: {commandLine}");
            parser.ProbeScript(commandLine, rewrite: true);
            return commandLine;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool CreateProcessAsUserA(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SecurityAttributes lpProcessAttributes, ref SecurityAttributes lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInfo lpProcessInformation);
        private bool CreateProcessAsUserA_Hooked(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SecurityAttributes lpProcessAttributes, ref SecurityAttributes lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInfo lpProcessInformation)
        {
            T("CreateProcessAsUserA( {0} ) CREATE_SUSPENDED", lpApplicationName);
            // Remember if the original call included CREATE_SUSPENDED
            bool callerSuspended = (dwCreationFlags & ProcessCreationFlags.CREATE_SUSPENDED) != 0;

            dwCreationFlags |= ProcessCreationFlags.CREATE_SUSPENDED;
            bool flag = CreateProcessAsUserA(hToken, lpApplicationName, lpCommandLine, ref lpProcessAttributes, ref lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation);
            if (lpProcessInformation.ProcessId != 0)
            {
                HookProcess(lpProcessInformation, callerSuspended);
            }
            // Only resume if the caller didn't want the process suspended
            if (!callerSuspended)
            {
                NativeMethods.ResumeThread(lpProcessInformation.hThread);
            }
            T("CreateProcessAsUserA ({0}) ResumeThread", lpApplicationName);
            return flag;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SecurityAttributes lpProcessAttributes, ref SecurityAttributes lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInfo lpProcessInformation);
        private bool CreateProcessAsUserW_Hooked(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref SecurityAttributes lpProcessAttributes, ref SecurityAttributes lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out ProcessInfo lpProcessInformation)
        {
            T("CreateProcessAsUserW( {0} ) CREATE_SUSPENDED", lpApplicationName);
            // Remember if the original call included CREATE_SUSPENDED
            bool callerSuspended = (dwCreationFlags & ProcessCreationFlags.CREATE_SUSPENDED) != 0;

            dwCreationFlags |= ProcessCreationFlags.CREATE_SUSPENDED;
            bool flag = CreateProcessAsUserW(hToken, lpApplicationName, lpCommandLine, ref lpProcessAttributes, ref lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, ref lpStartupInfo, out lpProcessInformation);
            if (lpProcessInformation.ProcessId != 0)
            {
                HookProcess(lpProcessInformation, callerSuspended);
            }
            // Only resume if the caller didn't want the process suspended
            if (!callerSuspended)
            {
                NativeMethods.ResumeThread(lpProcessInformation.hThread);
            }
            T("CreateProcessAsUserW ({0}) ResumeThread", lpApplicationName);
            return flag;
        }

        [DllImport("version.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool GetFileVersionInfoA(string lptstrFilename, int dwHandleIgnored, int dwLen, byte[] lpData);
        private static bool GetFileVersionInfoA_Hooked(string lptstrFilename, int dwHandleIgnored, int dwLen, byte[] lpData)
        {
            bool flag = GetFileVersionInfoA(lptstrFilename, dwHandleIgnored, dwLen, lpData);
            T("GetFileVersionInfoA {0}", lptstrFilename);
            return flag;
        }

        [DllImport("version.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetFileVersionInfoW(string lptstrFilename, int dwHandleIgnored, int dwLen, byte[] lpData);
        private static bool GetFileVersionInfoW_Hooked(string lptstrFilename, int dwHandleIgnored, int dwLen, byte[] lpData)
        {
            bool flag = GetFileVersionInfoW(lptstrFilename, dwHandleIgnored, dwLen, lpData);
            T("GetFileVersionInfoW {0}", lptstrFilename);
            return flag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern bool GetProductInfo(int dwOSMajorVersion, int dwOSMinorVersion, int dwSpMajorVersion, int dwSpMinorVersion, out int pdwReturnedProductType);
        private static bool GetProductInfo_Hooked(int dwOSMajorVersion, int dwOSMinorVersion, int dwSpMajorVersion, int dwSpMinorVersion, out int pdwReturnedProductType)
        {
            bool flag = GetProductInfo(dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, out pdwReturnedProductType);
            T("GetProductInfo({0},{1},{2},{3}) => {4}", dwOSMajorVersion, dwOSMinorVersion, dwSpMajorVersion, dwSpMinorVersion, (int)pdwReturnedProductType);
            return flag;
        }

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        private static extern long GetVersion();
        private static long GetVersion_Hooked()
        {
            long version = GetVersion();
            T("BEFORE GetVersion => Major [{0}] Minor [{1}]", version, version);
            version = 0x23f00206L;
            T("AFTER GetVersion => Major [{0}] Minor [{1}]", version, version);
            return version;
        }

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool GetVersionExA(ref OSVERSIONINFOEXA osvi);
        private static bool GetVersionExA_Hooked(ref OSVERSIONINFOEXA osvi)
        {
            bool versionExA = GetVersionExA(ref osvi);
            T("BEFORE GetVersionExA => Major [{0}] Minor [{1}] ProductType [{2}] Version [{3}] OSVersionInfoSize [{4}]", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.wProductType, osvi.szCSDVersion, osvi.dwOSVersionInfoSize);
            osvi.dwMajorVersion = 10;// 6;
            osvi.dwMinorVersion = 0; //3;
            osvi.wProductType = ProductType.VER_NT_SERVER;
            osvi.wServicePackMajor = 0;
            osvi.wServicePackMinor = 0;
            osvi.szCSDVersion = "";
            osvi.dwBuildNumber = 17763;// 0x23f0;
            osvi.wSuiteMask = 0;
            T("dwOSVersionInfoSize:   {0}", osvi.dwOSVersionInfoSize);
            T("dwMajorVersion:        {0}", osvi.dwMajorVersion);
            T("dwMinorVersion:        {0}", osvi.dwMinorVersion);
            T("dwBuildNumber:         {0}", osvi.dwBuildNumber);
            T("dwPlatformId:          {0}", osvi.dwPlatformId);
            T("szCSDVersion:          {0}", osvi.szCSDVersion);
            T("wServicePackMajor:     {0}", osvi.wServicePackMajor);
            T("wServicePackMinor:     {0}", osvi.wServicePackMinor);
            T("wSuiteMask:            {0}", osvi.wSuiteMask);
            T("wProductType:          {0}", osvi.wProductType);
            T("wReserved:             {0}", osvi.wReserved);
            T("AFTER GetVersionExA => Major [{0}] Minor [{1}] ProductType [{2}] Version [{3}]", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.wProductType, osvi.szCSDVersion);
            return versionExA;
        }

        [DllImport("kernel32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool GetVersionExW(ref OSVERSIONINFOEXW osvi);
        private static bool GetVersionExW_Hooked(ref OSVERSIONINFOEXW osvi)
        {
            bool versionExW = GetVersionExW(ref osvi);
            T("BEFORE GetVersionExW => Major [{0}] Minor [{1}] ProductType [{2}] Version [{3}] OSVersionInfoSize [{4}]", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.wProductType, osvi.szCSDVersion, osvi.dwOSVersionInfoSize);
            osvi.dwMajorVersion = 10;// 6;
            osvi.dwMinorVersion = 0; // 3;
            osvi.wProductType = ProductType.VER_NT_SERVER;
            osvi.wServicePackMajor = 0;
            osvi.wServicePackMinor = 0;
            osvi.szCSDVersion = "";
            osvi.dwBuildNumber = 17763;// 0x23f0;
            osvi.wSuiteMask = 0;
            T("dwOSVersionInfoSize:   {0}", osvi.dwOSVersionInfoSize);
            T("dwMajorVersion:        {0}", osvi.dwMajorVersion);
            T("dwMinorVersion:        {0}", osvi.dwMinorVersion);
            T("dwBuildNumber:         {0}", osvi.dwBuildNumber);
            T("dwPlatformId:          {0}", osvi.dwPlatformId);
            T("szCSDVersion:          {0}", osvi.szCSDVersion);
            T("wServicePackMajor:     {0}", osvi.wServicePackMajor);
            T("wServicePackMinor:     {0}", osvi.wServicePackMinor);
            T("wSuiteMask:            {0}", osvi.wSuiteMask);
            T("wProductType:          {0}", osvi.wProductType);
            T("wReserved:             {0}", osvi.wReserved);
            T("AFTER GetVersionExW => Major [{0}] Minor [{1}] ProductType [{2}] Version [{3}]", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.wProductType, osvi.szCSDVersion);
            return versionExW;
        }

        [DllImport("KERNEL32.DLL", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibraryA(string lpFileName);
        private static IntPtr LoadLibraryA_Hooked(string lpFileName)
        {
            T("LoadLibraryA({0})", lpFileName);
            return LoadLibraryA(lpFileName);
        }

        [DllImport("KERNEL32.DLL", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr LoadLibraryExA(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);
        private static IntPtr LoadLibraryExA_Hooked(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags)
        {
            T("LoadLibraryExA({0},{1},{2})", lpFileName, hReservedNull, dwFlags);
            return LoadLibraryExA(lpFileName, hReservedNull, dwFlags);
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryExW(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags);
        private static IntPtr LoadLibraryExW_Hooked(string lpFileName, IntPtr hReservedNull, LoadLibraryFlags dwFlags)
        {
            T("LoadLibraryExW({0},{1},{2})", lpFileName, hReservedNull, dwFlags);
            return LoadLibraryExW(lpFileName, hReservedNull, dwFlags);
        }

        [DllImport("KERNEL32.DLL", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryW(string lpFileName);
        private static IntPtr LoadLibraryW_Hooked(string lpFileName)
        {
            T("LoadLibraryW({0})", lpFileName);
            return LoadLibraryW(lpFileName);
        }

        [DllImport("User32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern int MessageBoxA(IntPtr hwnd, string lpText, string lpCaption, uint uType);
        private static int MessageBoxA_Hooked(IntPtr hwnd, string lpText, string lpCaption, uint uType)
        {
            int num = MessageBoxA(hwnd, lpText, "hooked::" + lpCaption, uType);
            T("MessageBoxA({0},{1})", lpText, lpCaption);
            return num;
        }

        [DllImport("User32.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int MessageBoxW(IntPtr hwnd, string lpText, string lpCaption, uint uType);
        private static int MessageBoxW_Hooked(IntPtr hwnd, string lpText, string lpCaption, uint uType)
        {
            int num = MessageBoxW(hwnd, lpText, "hooked::" + lpCaption, uType);
            T("MessageBoxW({0},{1})", lpText, lpCaption);
            return num;
        }

        [DllImport("ole32.dll")]
        private static extern int ProgIDFromCLSID([In] ref Guid clsid, [MarshalAs(UnmanagedType.LPWStr)] out string lplpszProgID);
        public void Run(RemoteHooking.IContext context, string channelName, bool hookChildren)
        {
            try
            {
                _callback = RemoteHooking.IpcConnectClient<CallbackInterface>(channelName);
                _callback.Message($"Run called channelName: {channelName} hookChildren: {hookChildren}");

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

                //this.RegOpenKeyExWHook = LocalHook.Create(LocalHook.GetProcAddress("advapi32.dll", "RegOpenKeyExW"), new DRegOpenKeyExW(Main.RegOpenKeyExW_Hooked), this);
                //this.RegOpenKeyExWHook.ThreadACL.SetExclusiveACL(new int[1]);
                //T("Hooked RegOpenKeyExW");
                /*  This rewrite needs to be commented for SharePoint 2016 to install */
                this.RegGetValueWHook = LocalHook.Create(LocalHook.GetProcAddress("advapi32.dll", "RegGetValueW"), new DRegGetValueW(Main.RegGetValueW_Hooked), this);
                this.RegGetValueWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked RegGetValueW");

                this.RegQueryValueExAHook = LocalHook.Create(LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueExA"), new DRegQueryValueExA(Main.RegQueryValueExA_Hooked), this);
                this.RegQueryValueExAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked RegQueryValueExA");

                this.RegQueryValueExWHook = LocalHook.Create(LocalHook.GetProcAddress("advapi32.dll", "RegQueryValueExW"), new DRegQueryValueExW(Main.RegQueryValueExW_Hooked), this);
                this.RegQueryValueExWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked RegQueryValueExW");
                /**/
                this.GetVersionExWHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "GetVersionExW"), new DGetVersionExW(Main.GetVersionExW_Hooked), this);
                this.GetVersionExWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked GetVersionExW");
                this.GetVersionExAHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "GetVersionExA"), new DGetVersionExA(Main.GetVersionExA_Hooked), this);
                this.GetVersionExAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked GetVersionExA");
                this.MessageBoxWHook = LocalHook.Create(LocalHook.GetProcAddress("User32.dll", "MessageBoxW"), new DMessageBoxW(Main.MessageBoxW_Hooked), this);
                this.MessageBoxWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked MessageBoxW");
                this.MessageBoxAHook = LocalHook.Create(LocalHook.GetProcAddress("User32.dll", "MessageBoxA"), new DMessageBoxA(Main.MessageBoxA_Hooked), this);
                this.MessageBoxAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked MessageBoxA");
                this.GetVersionHook = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "GetVersion"), new DGetVersion(Main.GetVersion_Hooked), this);
                this.GetVersionHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked GetVersion");
                this.CreateFileHookW = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"), new DCreateFileW(Main.CreateFileW_Hooked), this);
                this.CreateFileHookW.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CreateFileW");
                this.CreateFileHookA = LocalHook.Create(LocalHook.GetProcAddress("kernel32.dll", "CreateFileA"), new DCreateFileA(Main.CreateFileA_Hooked), this);
                this.CreateFileHookA.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CreateFileA");
                this.CreateProcessWHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "CreateProcessW"), new DCreateProcessW(CreateProcessW_Hooked), this);
                this.CreateProcessWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CreateProcessW");
                this.CreateProcessAHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "CreateProcessA"), new DCreateProcessA(CreateProcessA_Hooked), this);
                this.CreateProcessAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CreateProcessA");
                this.LoadLibraryWHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "LoadLibraryW"), new DLoadLibraryW(Main.LoadLibraryW_Hooked), this);
                this.LoadLibraryWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked LoadLibraryW");
                this.LoadLibraryAHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "LoadLibraryA"), new DLoadLibraryA(Main.LoadLibraryA_Hooked), this);
                this.LoadLibraryAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked LoadLibraryA");
                this.CoCreateInstanceHook = LocalHook.Create(LocalHook.GetProcAddress("ole32.dll", "CoCreateInstance"), new DCoCreateInstance(Main.CoCreateInstance_Hooked), this);
                this.CoCreateInstanceHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CoCreateInstance");
                this.CreateProcessAsUserWHook = LocalHook.Create(LocalHook.GetProcAddress("Advapi32.dll", "CreateProcessAsUserW"), new DCreateProcessAsUserW(CreateProcessAsUserW_Hooked), this);
                this.CreateProcessAsUserWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CreateProcessAsUserW");
                this.CreateProcessAsUserAHook = LocalHook.Create(LocalHook.GetProcAddress("Advapi32.dll", "CreateProcessAsUserA"), new DCreateProcessAsUserA(CreateProcessAsUserA_Hooked), this);
                this.CreateProcessAsUserAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked CreateProcessAsUserA");
                this.GetProductInfoHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "GetProductInfo"), new DGetProductInfo(Main.GetProductInfo_Hooked), this);
                this.GetProductInfoHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked GetProductInfo");
                this.ShellExecuteWHook = LocalHook.Create(LocalHook.GetProcAddress("Shell32.dll", "ShellExecuteW"), new DShellExecuteW(Main.ShellExecuteW_Hooked), this);
                this.ShellExecuteWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked ShellExecuteW");
                this.VerifyVersionInfoAHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "VerifyVersionInfoA"), new DVerifyVersionInfoA(Main.VerifyVersionInfoA_Hooked), this);
                this.VerifyVersionInfoAHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked VerifyVersionInfoA");
                this.VerifyVersionInfoWHook = LocalHook.Create(LocalHook.GetProcAddress("Kernel32.dll", "VerifyVersionInfoW"), new DVerifyVersionInfoW(Main.VerifyVersionInfoW_Hooked), this);
                this.VerifyVersionInfoWHook.ThreadACL.SetExclusiveACL(new int[1]);
                T("Hooked VerifyVersionInfoW");
            }
            catch (Exception exception)
            {
                _callback?.ReportException(exception);
                return;
            }
            var pid = RemoteHooking.GetCurrentProcessId();
            _callback?.IsInstalled(pid);
            RemoteHooking.WakeUpProcess();
            try
            {
                while (true)
                {
                    Thread.Sleep(1000);
                    _callback?.Message(pid.ToString());
                }
            }
            catch
            {
            }
        }

        [DllImport("shell32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr ShellExecuteW(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, ShowCommands nShowCmd);
        private static IntPtr ShellExecuteW_Hooked(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, ShowCommands nShowCmd)
        {
            IntPtr ptr = ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd);
            T("ShellExecuteW({0}, {1}, {2}, {3})", lpOperation, lpFile, lpParameters, lpDirectory);
            return ptr;
        }

        private static void T(string fmt, params object[] args)
        {
            Trace.WriteLine(string.Format(fmt, args));
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern bool VerifyVersionInfoA([In] ref OSVERSIONINFOEXA lpVersionInfo, TypeMask dwTypeMask, ulong dwlConditionMask);

        /*
        private static bool VerifyVersionInfoA_Hooked([In] ref OSVERSIONINFOEXA lpVersionInfo, TypeMask dwTypeMask, ulong dwlConditionMask)
        {
            bool flag = VerifyVersionInfoA(ref lpVersionInfo, dwTypeMask, dwlConditionMask);
            if (!flag)
            {
                flag = true;
                T("Changing return to true :: VerifyVersionInfoA({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
                return flag;
            }
            T("VerifyVersionInfoA({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
            return flag;
        }
        */
        private static bool VerifyVersionInfoA_Hooked([In] ref OSVERSIONINFOEXA lpVersionInfo, TypeMask dwTypeMask, ulong dwlConditionMask)
        {
            bool flag = VerifyVersionInfoA(ref lpVersionInfo, dwTypeMask, dwlConditionMask);
            if (!flag)
            {
                if (dwlConditionMask != 9223372036854776024L)
                {
                    flag = true;
                    T("Changing return to true :: VerifyVersionInfoA({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
                    return flag;
                }
                T("Not Changing return to true :: VerifyVersionInfoA({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
                return flag;
            }
            T("VerifyVersionInfoA({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
            return flag;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool VerifyVersionInfoW([In] ref OSVERSIONINFOEXW lpVersionInfo, TypeMask dwTypeMask, ulong dwlConditionMask);
        private static bool VerifyVersionInfoW_Hooked([In] ref OSVERSIONINFOEXW lpVersionInfo, TypeMask dwTypeMask, ulong dwlConditionMask)
        {
            bool flag = VerifyVersionInfoW(ref lpVersionInfo, dwTypeMask, dwlConditionMask);
            TraceVersionInfo(lpVersionInfo, dwTypeMask);

            if (!flag)
            {
                if (dwlConditionMask != 9223372036854776024L)
                {
                    flag = true;
                    T("Changing return to true :: VerifyVersionInfoW({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
                    return flag;
                }
                T("Not Changing return to true :: VerifyVersionInfoW({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
                return flag;
            }
            T("VerifyVersionInfoW({0}, {1}) => {2}", dwTypeMask, dwlConditionMask, flag);
            return flag;
        }

        private static void TraceVersionInfo(OSVERSIONINFOEXW lpVersionInfo, TypeMask mask)
        {
            T("dwOSVersionInfoSize [{0}]", lpVersionInfo.dwOSVersionInfoSize);
            T("dwMajorVersion      [{0}]", lpVersionInfo.dwMajorVersion);
            T("dwMinorVersion      [{0}]", lpVersionInfo.dwMinorVersion);
            T("dwBuildNumber       [{0}]", lpVersionInfo.dwBuildNumber);
            T("dwPlatformId        [{0}]", lpVersionInfo.dwPlatformId);
            T("szCSDVersion        [{0}]", lpVersionInfo.szCSDVersion);
            T("wServicePackMajor   [{0}]", lpVersionInfo.wServicePackMajor);
            T("wServicePackMinor   [{0}]", lpVersionInfo.wServicePackMinor);
            T("wSuiteMask          [{0}]", lpVersionInfo.wSuiteMask);
            T("wProductType        [{0}]", lpVersionInfo.wProductType);
            T("wReserved           [{0}]", lpVersionInfo.wReserved);

            T("Testing {0}", mask);
        }

        [Flags]
        private enum CLSCTX : uint
        {
            CLSCTX_ACTIVATE_32_BIT_SERVER = 0x40000,
            CLSCTX_ACTIVATE_64_BIT_SERVER = 0x80000,
            CLSCTX_ALL = 0x17,
            CLSCTX_DISABLE_AAA = 0x8000,
            CLSCTX_ENABLE_AAA = 0x10000,
            CLSCTX_ENABLE_CODE_DOWNLOAD = 0x2000,
            CLSCTX_FROM_DEFAULT_CONTEXT = 0x20000,
            CLSCTX_INPROC = 3,
            CLSCTX_INPROC_HANDLER = 2,
            CLSCTX_INPROC_HANDLER16 = 0x20,
            CLSCTX_INPROC_SERVER = 1,
            CLSCTX_INPROC_SERVER16 = 8,
            CLSCTX_LOCAL_SERVER = 4,
            CLSCTX_NO_CODE_DOWNLOAD = 0x400,
            CLSCTX_NO_CUSTOM_MARSHAL = 0x1000,
            CLSCTX_NO_FAILURE_LOG = 0x4000,
            CLSCTX_REMOTE_SERVER = 0x10,
            CLSCTX_RESERVED1 = 0x40,
            CLSCTX_RESERVED2 = 0x80,
            CLSCTX_RESERVED3 = 0x100,
            CLSCTX_RESERVED4 = 0x200,
            CLSCTX_RESERVED5 = 0x800,
            CLSCTX_SERVER = 0x15
        }
        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate uint DRegOpenKeyExW(UIntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, UIntPtr phkResult);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate uint DRegGetValueW(IntPtr hKey, string lpSubKey, string lpValue, uint dwFlags, IntPtr pdwType, IntPtr pvData, IntPtr pcbData);


        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate int DRegQueryValueExA(IntPtr hKey, [In] string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, ref int lpcbData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate int DRegQueryValueExW(IntPtr hKey, [In] string lpValueName, IntPtr lpReserved, IntPtr lpType, IntPtr lpData, ref int lpcbData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate uint DCoCreateInstance([In, MarshalAs(UnmanagedType.LPStruct)] Guid rclsid, IntPtr pUnkOuter, uint dwClsContext, [In, MarshalAs(UnmanagedType.LPStruct)] Guid riid, out IntPtr ppv);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate IntPtr DCreateFileA(string InFileName, uint InDesiredAccess, uint InShareMode, IntPtr InSecurityAttributes, uint InCreationDisposition, uint InFlagsAndAttributes, IntPtr InTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr DCreateFileW(string InFileName, uint InDesiredAccess, uint InShareMode, IntPtr InSecurityAttributes, uint InCreationDisposition, uint InFlagsAndAttributes, IntPtr InTemplateFile);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate bool DCreateProcessA(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Main.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out Main.ProcessInfo lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate bool DCreateProcessAsUserA(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref Main.SecurityAttributes lpProcessAttributes, ref Main.SecurityAttributes lpThreadAttributes, bool bInheritHandles, Main.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref Main.STARTUPINFO lpStartupInfo, out Main.ProcessInfo lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DCreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, ref Main.SecurityAttributes lpProcessAttributes, ref Main.SecurityAttributes lpThreadAttributes, bool bInheritHandles, Main.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref Main.STARTUPINFO lpStartupInfo, out Main.ProcessInfo lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DCreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, Main.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, IntPtr lpStartupInfo, out Main.ProcessInfo lpProcessInformation);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate bool DGetFileVersionInfoA(string lptstrFilename, int dwHandleIgnored, int dwLen, byte[] lpData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DGetFileVersionInfoW(string lptstrFilename, int dwHandleIgnored, int dwLen, byte[] lpData);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        private delegate bool DGetProductInfo(int dwOSMajorVersion, int dwOSMinorVersion, int dwSpMajorVersion, int dwSpMinorVersion, out int pdwReturnedProductType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Auto, SetLastError = true)]
        private delegate long DGetVersion();

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate bool DGetVersionExA(ref Main.OSVERSIONINFOEXA osvi);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DGetVersionExW(ref Main.OSVERSIONINFOEXW osvi);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate IntPtr DLoadLibraryA(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate IntPtr DLoadLibraryExA(string lpFileName, IntPtr hReservedNull, Main.LoadLibraryFlags dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr DLoadLibraryExW(string lpFileName, IntPtr hReservedNull, Main.LoadLibraryFlags dwFlags);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr DLoadLibraryW(string lpFileName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        private delegate int DMessageBoxA(IntPtr hwnd, string lpText, string lpCaption, uint uType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate int DMessageBoxW(IntPtr hwnd, string lpText, string lpCaption, uint uType);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate IntPtr DShellExecuteW(IntPtr hwnd, string lpOperation, string lpFile, string lpParameters, string lpDirectory, Main.ShowCommands nShowCmd);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DVerifyVersionInfoA([In] ref Main.OSVERSIONINFOEXA lpVersionInfo, Main.TypeMask dwTypeMask, ulong dwlConditionMask);

        [UnmanagedFunctionPointer(CallingConvention.StdCall, CharSet = CharSet.Unicode, SetLastError = true)]
        private delegate bool DVerifyVersionInfoW([In] ref Main.OSVERSIONINFOEXW lpVersionInfo, Main.TypeMask dwTypeMask, ulong dwlConditionMask);

        [Flags]
        private enum LoadLibraryFlags : uint
        {
            DONT_RESOLVE_DLL_REFERENCES = 1,
            LOAD_IGNORE_CODE_AUTHZ_LEVEL = 0x10,
            LOAD_LIBRARY_AS_DATAFILE = 2,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE = 0x40,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x20,
            LOAD_WITH_ALTERED_SEARCH_PATH = 8
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OSVERSIONINFOEXA
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public Main.SuiteMask wSuiteMask;
            public Main.ProductType wProductType;
            public byte wReserved;

            //[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x80)]
            //public string szBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OSVERSIONINFOEXW
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
            public ushort wServicePackMajor;
            public ushort wServicePackMinor;
            public Main.SuiteMask wSuiteMask;
            public Main.ProductType wProductType;
            public byte wReserved;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x80)]
            public string szBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct OSVERSIONINFO
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 0x80)]
            public string szCSDVersion;
        }


        [Flags]
        public enum ProcessCreationFlags : uint
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x1000000,
            CREATE_DEFAULT_ERROR_MODE = 0x4000000,
            CREATE_NEW_CONSOLE = 0x10,
            CREATE_NEW_PROCESS_GROUP = 0x200,
            CREATE_NO_WINDOW = 0x8000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x2000000,
            CREATE_PROTECTED_PROCESS = 0x40000,
            CREATE_SEPARATE_WOW_VDM = 0x1000,
            CREATE_SHARED_WOW_VDM = 0x1000,
            CREATE_SUSPENDED = 4,
            CREATE_UNICODE_ENVIRONMENT = 0x400,
            DEBUG_ONLY_THIS_PROCESS = 2,
            DEBUG_PROCESS = 1,
            DETACHED_PROCESS = 8,
            EXTENDED_STARTUPINFO_PRESENT = 0x80000,
            INHERIT_PARENT_AFFINITY = 0x10000,
            ZERO_FLAG = 0
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int ProcessId;
            public int ThreadId;
        }
        private enum ProductType : byte
        {
            VER_NT_DOMAIN_CONTROLLER = 2,
            VER_NT_SERVER = 3,
            VER_NT_WORKSTATION = 1
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct SecurityAttributes
        {
            public int length;
            public IntPtr lpSecurityDescriptor;
            public bool bInheritHandle;
        }

        public enum ShowCommands
        {
            SW_FORCEMINIMIZE = 11,
            SW_HIDE = 0,
            SW_MAX = 11,
            SW_MAXIMIZE = 3,
            SW_MINIMIZE = 6,
            SW_NORMAL = 1,
            SW_RESTORE = 9,
            SW_SHOW = 5,
            SW_SHOWDEFAULT = 10,
            SW_SHOWMAXIMIZED = 3,
            SW_SHOWMINIMIZED = 2,
            SW_SHOWMINNOACTIVE = 7,
            SW_SHOWNA = 8,
            SW_SHOWNOACTIVATE = 4,
            SW_SHOWNORMAL = 1
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct StartupInfoA
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct StartupInfoW
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
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

        [Flags]
        private enum TypeMask : uint
        {
            VER_BUILDNUMBER = 4,
            VER_MAJORVERSION = 2,
            VER_MINORVERSION = 1,
            VER_PLATFORMID = 8,
            VER_PRODUCT_TYPE = 0x80,
            VER_SERVICEPACKMAJOR = 0x20,
            VER_SERVICEPACKMINOR = 0x10,
            VER_SUITENAME = 0x40
        }
    }
}

