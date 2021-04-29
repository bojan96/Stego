using System;
using System.Buffers.Binary;
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
            Span<byte> lengthSpan = new Span<byte>(dstArray, 0, 4);
            BinaryPrimitives.WriteInt32BigEndian(lengthSpan, array1.Length);
            array1.CopyTo(dstArray, sizeof(int));
            array2.CopyTo(dstArray, sizeof(int) + array1.Length);

            return dstArray;
        }

        public static (byte[], byte[]) SplitArray(byte[] array)
        {
            Span<byte> lengthSpan = new Span<byte>(array, 0, 4);

            int array1Len = BinaryPrimitives.ReadInt32BigEndian(lengthSpan);
            int array2Len = array.Length - sizeof(int) - array1Len;
            var array1 = new byte[array1Len];
            var array2 = new byte[array2Len];
            Array.Copy(array, sizeof(int), array1, 0, array1Len);
            Array.Copy(array, sizeof(int) + array1Len, array2, 0, array2Len);

            return (array1, array2);

        }
    }
}
