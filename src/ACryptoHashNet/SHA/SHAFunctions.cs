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
    }
}
