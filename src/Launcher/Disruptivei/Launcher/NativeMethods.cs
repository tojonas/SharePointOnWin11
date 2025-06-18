namespace Disruptivei.Launcher
{
    using System;
    using System.Runtime.InteropServices;

    public static class NativeMethods
    {
        public const uint INFINITE = uint.MaxValue;
        public const uint WAIT_ABANDONED = 0x80;
        public const uint WAIT_OBJECT_0 = 0;
        public const uint WAIT_TIMEOUT = 0x102;

        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [return: MarshalAs(UnmanagedType.Bool)]
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);
        [DllImport("kernel32.dll")]
        public static extern uint ResumeThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
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

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
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
    }
}

