using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    internal static class SHAFunctions
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ch(uint x, uint y, uint z)
        {
            return (x & y) ^ (~x & z);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Ch(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (~x & z);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Maj(uint x, uint y, uint z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Maj(ulong x, ulong y, ulong z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Parity(uint x, uint y, uint z)
        {
            return x ^ y ^ z;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Parity(ulong x, ulong y, ulong z)
        {
            return x ^ y ^ z;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ro0(uint x)
        {
            return Bits.RotateRight(x, 7) ^ Bits.RotateRight(x, 18) ^ (x >> 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Ro0(ulong x)
        {
            return Bits.RotateRight(x, 1) ^ Bits.RotateRight(x, 8) ^ (x >> 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ro1(uint x)
        {
            return Bits.RotateRight(x, 17) ^ Bits.RotateRight(x, 19) ^ (x >> 10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Ro1(ulong x)
        {
            return Bits.RotateRight(x, 19) ^ Bits.RotateRight(x, 61) ^ (x >> 6);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Sig0(uint x)
        {
            return Bits.RotateRight(x, 2) ^ Bits.RotateRight(x, 13) ^ Bits.RotateRight(x, 22);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Sig0(ulong x)
        {
            return Bits.RotateRight(x, 28) ^ Bits.RotateRight(x, 34) ^ Bits.RotateRight(x, 39);
        }        

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Sig1(uint x)
        {
            return Bits.RotateRight(x, 6) ^ Bits.RotateRight(x, 11) ^ Bits.RotateRight(x, 25);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Sig1(ulong x)
        {
            return Bits.RotateRight(x, 14) ^ Bits.RotateRight(x, 18) ^ Bits.RotateRight(x, 41);
        }
    }
}
