using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    internal static class SHAFunctions32
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ro0(uint x) => x.RotateRight(7) ^ x.RotateRight(18) ^ (x >> 3);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ro1(uint x) => x.RotateRight(17) ^ x.RotateRight(19) ^ (x >> 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Ch(uint x, uint y, uint z) => (x & y) ^ (~x & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Maj(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Parity(uint x, uint y, uint z) => x ^ y ^ z;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Sig0(uint x) => x.RotateRight(2) ^ x.RotateRight(13) ^ x.RotateRight(22);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint Sig1(uint x) => x.RotateRight(6) ^ x.RotateRight(11) ^ x.RotateRight(25);
    }
}
