using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    public static class LittleEndianBuffer
    {
        public static void BlockCopy(uint[] src, int srcOffset, byte[] dst, int dstOffset, int bytesCount)
        {
            if (srcOffset < 0 || srcOffset > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(srcOffset));
            }

            if (dstOffset < 0 || dstOffset > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dstOffset));
            }

            if (bytesCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            int uintsCount = bytesCount >> 2; // arg / 4
            int bytesRemaining = bytesCount & 0x3; // arg % 4

            if (bytesRemaining > 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            if (srcOffset + uintsCount > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }   

            if (dstOffset + bytesCount > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }  
            
            for (int srcIndex = srcOffset, dstIndex = dstOffset; 
                dstIndex < dstOffset + bytesCount; 
                srcIndex += 1, dstIndex += 4)
            {
                CopyLittleEndianUInt32ToBytes(src[srcIndex], dst.AsSpan(dstIndex, 4));
            }
        }

        public static void BlockCopy(byte[] src, int srcOffset, uint[] dst, int dstOffset, int bytesCount)
        {
            if (srcOffset < 0 || srcOffset > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(srcOffset));
            }

            if (dstOffset < 0 || dstOffset > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dstOffset));
            }

            if (bytesCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            int uintsCount = bytesCount >> 2; // arg / 4
            int bytesRemaining = bytesCount & 0x3; // arg % 4

            if (bytesRemaining > 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            if (srcOffset + bytesCount > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }                                    

            if (dstOffset + uintsCount > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }            

            for (int srcIndex = srcOffset, dstIndex = dstOffset;
                srcIndex < srcOffset + bytesCount;
                srcIndex += 4, dstIndex += 1)
            {
                dst[dstIndex] = BytesToLittleEndianUInt32(src.AsSpan(srcIndex, 4));
            }
        }

        public static void BlockCopy(ulong[] src, int srcOffset, byte[] dst, int dstOffset, int bytesCount)
        {
            if (srcOffset < 0 || srcOffset > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(srcOffset));
            }

            if (dstOffset < 0 || dstOffset > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dstOffset));
            }

            if (bytesCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            int ulongsCount = bytesCount >> 3; // arg / 8
            int bytesRemaining = bytesCount & 0x7; // arg % 8            

            if (bytesRemaining > 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            if (srcOffset + ulongsCount > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            if (dstOffset + bytesCount > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            for (int srcIndex = srcOffset, dstIndex = dstOffset; 
                dstIndex < dstOffset + bytesCount;
                srcIndex += 1, dstIndex += 8)
            {
                CopyLittleEndianUInt64ToBytes(src[srcIndex], dst.AsSpan(dstIndex, 8));
            }
        }

        public static void BlockCopy(byte[] src, int srcOffset, ulong[] dst, int dstOffset, int bytesCount)
        {
            if (srcOffset < 0 || srcOffset > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(srcOffset));
            }

            if (dstOffset < 0 || dstOffset > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(dstOffset));
            }

            if (bytesCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            int ulongsCount = bytesCount >> 3; // arg / 8
            int bytesRemaining = bytesCount & 0x7; // arg % 8

            if (bytesRemaining > 0)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            if (srcOffset + bytesCount > src.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }                                    

            if (dstOffset + ulongsCount > dst.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(bytesCount));
            }

            for (int srcIndex = srcOffset, dstIndex = dstOffset;
                srcIndex < srcOffset + bytesCount;
                srcIndex += 8, dstIndex += 1)
            {
                dst[dstIndex] = BytesToLittleEndianUInt64(src.AsSpan(srcIndex, 8));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CopyLittleEndianUInt32ToBytes(uint input, Span<byte> bytes)
        {
            bytes[0] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[1] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[2] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[3] = unchecked((byte)(input & 0xff));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BytesToLittleEndianUInt32(ReadOnlySpan<byte> bytes)
        {
            uint result = bytes[3];
            result = unchecked(result << 8 | bytes[2]);
            result = unchecked(result << 8 | bytes[1]);
            result = unchecked(result << 8 | bytes[0]);
            return result;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CopyLittleEndianUInt64ToBytes(ulong input, Span<byte> bytes)
        {
            bytes[0] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[1] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[2] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[3] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[4] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[5] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[6] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[7] = unchecked((byte)(input & 0xff));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong BytesToLittleEndianUInt64(ReadOnlySpan<byte> bytes)
        {
            ulong result = bytes[7];
            result = unchecked(result << 8 | bytes[6]);
            result = unchecked(result << 8 | bytes[5]);
            result = unchecked(result << 8 | bytes[4]);
            result = unchecked(result << 8 | bytes[3]);
            result = unchecked(result << 8 | bytes[2]);
            result = unchecked(result << 8 | bytes[1]);
            result = unchecked(result << 8 | bytes[0]);
            return result;
        }
    }
}
