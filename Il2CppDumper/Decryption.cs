using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Il2CppDumper
{
    internal class Decryption
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private extern static IntPtr LoadLibrary(string path);

        [DllImport("kernel32.dll", SetLastError = true)]
        private extern static IntPtr GetProcAddress(IntPtr lib, string funcName);

        [DllImport("kernel32.dll")]
        private extern static bool FreeLibrary(IntPtr lib);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr DecryptMetadata_t(byte[] data, int length);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr GetStringFromIndex_t(byte[] data, uint index);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr GetStringLiteralFromIndex_t(byte[] data, uint index, ref int len);

        static byte[] finalMetaBuffer;

        static IntPtr libHandle;

        static IntPtr decryptMeta;
        static IntPtr getStringFromIndex;
        static IntPtr getStringLiteralFromIndex;

        static DecryptMetadata_t decryptMetaFunc;
        static GetStringFromIndex_t getStringFromIndexFunc;
        static GetStringLiteralFromIndex_t getStringLiteralFromIndexFunc;

        static int decryptMetaOffset = 0xC9B10;
        static int getStringFromIndexOffset = 0x51710;
        static int getStringLiteralFromIndexOffset = 0x51910;

        static public void initDecrypt()
        {
            libHandle = LoadLibrary("UnityPlayer.dll");
            decryptMeta = libHandle + decryptMetaOffset;
            getStringFromIndex = libHandle + getStringFromIndexOffset;
            getStringLiteralFromIndex = libHandle + getStringLiteralFromIndexOffset;
            decryptMetaFunc = (DecryptMetadata_t)Marshal.GetDelegateForFunctionPointer(decryptMeta, typeof(DecryptMetadata_t));
            getStringFromIndexFunc = (GetStringFromIndex_t)Marshal.GetDelegateForFunctionPointer(getStringFromIndex, typeof(GetStringFromIndex_t));
            getStringLiteralFromIndexFunc = (GetStringLiteralFromIndex_t)Marshal.GetDelegateForFunctionPointer(getStringLiteralFromIndex, typeof(GetStringLiteralFromIndex_t));
        }

        static public byte[] decryptMetadata(byte[] data)
        {
            IntPtr decryptedMeta = decryptMetaFunc(data, data.Length);
            byte[] finalMeta = new byte[data.Length];
            Marshal.Copy(decryptedMeta, finalMeta, 0, finalMeta.Length);

            var key = new byte[] { 0x3F, 0x73, 0xA8, 0x5A, 0x8, 0x32, 0xA, 0x33, 0x3C, 0xFA, 0x8D, 0x4E, 0x8B, 0xC, 0x77, 0x45 };
            var step = (int)(finalMeta.Length >> 14) << 6;

            for (var pos = 0; pos < finalMeta.Length; pos += step)
                for (var b = 0; b < 0x10; b++)
                    finalMeta[pos + b] ^= key[b];

            finalMetaBuffer = finalMeta;

            return finalMeta;
        }
        static public string getString(uint index)
        {
            return Marshal.PtrToStringAnsi(getStringFromIndexFunc(finalMetaBuffer, index));
        }

        static public string getStringLiteral(uint index)
        {
            int len = 0;
            IntPtr stringPtr = getStringLiteralFromIndexFunc(finalMetaBuffer, index, ref len);
            byte[] stringBuff = new byte[len];
            Marshal.Copy(stringPtr, stringBuff, 0, len);
            return Encoding.UTF8.GetString(stringBuff);
        }
    }
}
