using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace Patch
{
    public class Helper
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr GetProcAddress(IntPtr hModule, string procName);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr LoadLibrary(string name);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate UInt32 NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref IntPtr regionSize, UInt32 newProtect, ref UInt32 oldProtect);

        public static byte[] A3ZEEPatch
        {
            get
            {
                if (Is64Bit)
                {
                    byte[] magic64 = ConvertToByteArray("B85" + "700" + "078" + "0C3");
                    return magic64;
                }

                byte[] magic86 = ConvertToByteArray("B85" + "700" + "078" + "0C2" + "1800");
                return magic86;
            }
        }

        public static byte[] ETVVPatch
        {
            get
            {
                if (Is64Bit)
                {
                    byte[] magic64 = ConvertToByteArray("483" + "3c0" + "c3");
                    return magic64;
                }

                byte[] magic86 = ConvertToByteArray("33c" + "0c2" + "1400");
                return magic86;
            }
        }

        public static bool Is64Bit
        {
            get
            {
                return IntPtr.Size == 8;
            }
        }

        public static byte[] ConvertToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }
    }
}
