using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Stego
{
    public static class Utility
    {
        public static byte[] CombineByteArrays(byte[] array1, byte[] array2)
        {

            var dstArray = new byte[sizeof(int) + array1.Length + array2.Length];
            BitConverter.GetBytes(array1.Length).CopyTo(dstArray, 0);
            array1.CopyTo(dstArray, sizeof(int));
            array2.CopyTo(dstArray, sizeof(int) + array1.Length);

            return dstArray;
        }

        public static (byte[], byte[]) SplitArray(byte[] array)
        {

            int array1Len = BitConverter.ToInt32(array.Take(sizeof(int)).ToArray(), 0);
            int array2Len = array.Length - sizeof(int) - array1Len;
            var array1 = new byte[array1Len];
            var array2 = new byte[array2Len];
            Array.Copy(array, sizeof(int), array1, 0, array1Len);
            Array.Copy(array, sizeof(int) + array1Len, array2, 0, array2Len);

            return (array1, array2);

        }
    }
}
