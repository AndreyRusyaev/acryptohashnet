using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    internal static class SHAFunctions64
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Ro0(ulong x) => x.RotateRight(1) ^ x.RotateRight(8) ^ (x >> 7);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Ro1(ulong x) => x.RotateRight(19) ^ x.RotateRight(61) ^ (x >> 6);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Ch(ulong x, ulong y, ulong z) => (x & y) ^ (~x & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Maj(ulong x, ulong y, ulong z) => (x & y) ^ (x & z) ^ (y & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Parity(ulong x, ulong y, ulong z) => x ^ y ^ z;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Sig0(ulong x) => x.RotateRight(28) ^ x.RotateRight(34) ^ x.RotateRight(39);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static ulong Sig1(ulong x) => x.RotateRight(14) ^ x.RotateRight(18) ^ x.RotateRight(41);
    }
}
