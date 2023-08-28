using System.Diagnostics;
using System.Runtime.InteropServices;

namespace GettingProcessIntegrityLevel2
{
    internal class Program
    {
        // TokenHandle must have TOKEN_QUERY_SOURCE access rights (src MSDN)
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TokenInformationClass TokenInformationClass,
            IntPtr TokenInformation,
            uint TokenInformationLength,
            out uint ReturnLength);
        
        public enum TokenInformationClass
        {
            TokenIntegrityLevel = 25
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }
        
        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthority(
            IntPtr sid, 
            UInt32 subAuthorityIndex);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);

        // https://www.pinvoke.net/default.aspx/Structures/SID_IDENTIFIER_AUTHORITY.html
        public struct SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] Value;

            public SID_IDENTIFIER_AUTHORITY(byte[] value)
            {
                Value = value;
            }
        }

        // ProcessHandle must have PROCESS_QUERY_LIMITED_INFORMATION access rights (src MSDN)
        // DesiredAccess -- recommended : TOKEN_ALL_ACCESS
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess, 
            out IntPtr TokenHandle);

        // security RID constants
        // ..._PLUS_RID => + 0x100, e.g. MEDIUM_PLUS, SYSTEM_PLUS, etc.
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
        // https://stackoverflow.com/q/12774738
        public static uint SECURITY_MANDATORY_UNTRUSTED_RID = 0x00000000;
        public static uint SECURITY_MANDATORY_LOW_RID = 0x00001000;
        public static uint SECURITY_MANDATORY_MEDIUM_RID = 0x00002000;
        public static uint SECURITY_MANDATORY_HIGH_RID = 0x00003000;
        public static uint SECURITY_MANDATORY_SYSTEM_RID = 0x00004000;
        public static uint SECURITY_MANDATORY_PROTECTED_PROCESS_RID = 0x00005000;

        // process access rights constants
        // https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
        //public static uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        //public static uint PROCESS_QUERY_INFORMATION = 0x0400;

        // token access rights constants
        // https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects
        //public static uint TOKEN_QUERY_SOURCE = 0x0010;  // https://grep.app/search?q=TOKEN_QUERY_SOURCE
        public static uint TOKEN_ALL_ACCESS = 0x000F01FF;  // https://grep.app/search?q=TOKEN_ALL_ACCESS%20%3D

        static void Main(string[] args)
        {
            foreach (Process proc in Process.GetProcesses())
            {
                try
                {
                    if (proc.Responding && !proc.HasExited)
                        Console.WriteLine(
                            "{2:X} {0} {1}", 
                            proc.ProcessName, 
                            proc.Id, 
                            GetProcessIntegrityLevelRID(proc));  // {n:X} nth format arg in hexadecimal
                }
                catch (Exception e)  // "access is denied", "process has exited"
                { 
                    //Console.WriteLine(e.ToString()); 
                }
            }
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
