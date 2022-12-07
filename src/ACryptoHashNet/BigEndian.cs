using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    public static class BigEndian
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ToByteArray(ReadOnlySpan<uint> input)
        {
            byte[] result = new byte[input.Length * 4];

            Copy(input, result.AsSpan());

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] ToByteArray(ReadOnlySpan<ulong> input)
        {
            byte[] result = new byte[input.Length * 8];

            Copy(input, result.AsSpan());

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint[] ToUInt32Array(ReadOnlySpan<byte> input)
        {
            uint[] result = new uint[input.Length / 4];

            Copy(input, result.AsSpan());

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong[] ToUInt64Array(ReadOnlySpan<byte> input)
        {
            ulong[] result = new ulong[input.Length / 8];

            Copy(input, result.AsSpan());

            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy(ReadOnlySpan<uint> src, Span<byte> dst)
        {
            for (int srcIndex = 0, dstIndex = 0; srcIndex < src.Length && dstIndex <= dst.Length - 4; srcIndex += 1, dstIndex += 4)
            {
                Copy(src[srcIndex], dst.Slice(dstIndex, 4));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy(ReadOnlySpan<byte> src, Span<uint> dst)
        {
            for (int srcIndex = 0, dstIndex = 0; srcIndex <= src.Length - 4 && dstIndex < dst.Length; srcIndex += 4, dstIndex += 1)
            {
                dst[dstIndex] = ToUInt32(src.Slice(srcIndex, 4));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy(ReadOnlySpan<ulong> src, Span<byte> dst)
        {
            for (int srcIndex = 0, dstIndex = 0; srcIndex < src.Length && dstIndex <= dst.Length - 8; srcIndex += 1, dstIndex += 8)
            {
                Copy(src[srcIndex], dst.Slice(dstIndex, 8));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy(ReadOnlySpan<byte> src, Span<ulong> dst)
        {
            for (int srcIndex = 0, dstIndex = 0; srcIndex <= src.Length - 8 && dstIndex < dst.Length; srcIndex += 8, dstIndex += 1)
            {
                dst[dstIndex] = ToUInt64(src.Slice(srcIndex, 8));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy(uint input, Span<byte> bytes)
        {
            if (bytes.Length < 4)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            bytes[0] = (byte)(input >> 24);
            bytes[1] = (byte)(input >> 16);
            bytes[2] = (byte)(input >> 8);
            bytes[3] = (byte)input;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Copy(ulong input, Span<byte> bytes)
        {
            if (bytes.Length < 8)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            bytes[0] = (byte)(input >> 56);
            bytes[1] = (byte)(input >> 48);
            bytes[2] = (byte)(input >> 40);
            bytes[3] = (byte)(input >> 32);
            bytes[4] = (byte)(input >> 24);
            bytes[5] = (byte)(input >> 16);
            bytes[6] = (byte)(input >> 8);
            bytes[7] = (byte)input;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint ToUInt32(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < 4)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            return bytes[3]
                | ((uint)bytes[2] << 8)
                | ((uint)bytes[1] << 16)
                | ((uint)bytes[0] << 24);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong ToUInt64(ReadOnlySpan<byte> bytes)
        {
            if (bytes.Length < 8)
            {
                throw new ArgumentOutOfRangeException(nameof(bytes));
            }

            return bytes[7]
                | ((ulong)bytes[6] << 8)
                | ((ulong)bytes[5] << 16)
                | ((ulong)bytes[4] << 24)
                | ((ulong)bytes[3] << 32)
                | ((ulong)bytes[2] << 40)
                | ((ulong)bytes[1] << 48)
                | ((ulong)bytes[0] << 56);
        }
    }
}
