using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// RIPEMD-160 is a 160-bit cryptographic hash function, designed by Hans Dobbertin, Antoon Bosselaers, and Bart Preneel.
    /// https://homes.esat.kuleuven.be/~bosselae/ripemd160.html
    /// </summary>
    public sealed class RIPEMD160 : BlockHashAlgorithm
    {
        #region Constants

        private static readonly uint[] Constants1 = new uint[]
        {
            0x00000000,
            0x5a827999, // [2 ^ 30 * sqrt(2)]
            0x6ed9eba1, // [2 ^ 30 * sqrt(3)]
            0x8f1bbcdc, // [2 ^ 30 * sqrt(5)]
            0xa953fd4e  // [2 ^ 30 * sqrt(7)]
        };

        private static readonly uint[] WordOrders1 = new uint[]
        {
            // round 1
            00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 10, 11, 12, 13, 14, 15,
            // round 2
            07, 04, 13, 01, 10, 06, 15, 03, 12, 00, 09, 05, 02, 14, 11, 08,
            // round 3
            03, 10, 14, 04, 09, 15, 08, 01, 02, 07, 00, 06, 13, 11, 05, 12,
            // round 4
            01, 09, 11, 10, 00, 08, 12, 04, 13, 03, 07, 15, 14, 05, 06, 02,
            // round 5
            04, 00, 05, 09, 07, 12, 02, 10, 14, 01, 03, 08, 11, 06, 15, 13
        };

        private static readonly int[] Shifts1 = new int[]
        {
            // round 1
            11, 14, 15, 12, 05, 08, 07, 09, 11, 13, 14, 15, 06, 07, 09, 08,
            // round 2
            07, 06, 08, 13, 11, 09, 07, 15, 07, 12, 15, 09, 11, 07, 13, 12,
            // round 3
            11, 13, 06, 07, 14, 09, 13, 15, 14, 08, 13, 06, 05, 12, 07, 05,
            // round 4
            11, 12, 14, 15, 14, 15, 09, 08, 09, 14, 05, 06, 08, 06, 05, 12,
            // round 5
            09, 15, 05, 11, 06, 08, 13, 12, 05, 12, 13, 14, 11, 08, 05, 06
        };

        private static readonly uint[] Constants2 = new uint[]
        {
            // root3: its root from 3 degree
            0x50a28be6, // [2 ^ 30 * root3(2)]
            0x5c4dd124, // [2 ^ 30 * root3(3)]
            0x6d703ef3, // [2 ^ 30 * root3(5)]
            0x7a6d76e9, // [2 ^ 30 * root3(7)]
            0x00000000
        };

        private static readonly uint[] WordOrders2 = new uint[]
        {
            // round 1
            05, 14, 07, 00, 09, 02, 11, 04, 13, 06, 15, 08, 01, 10, 03, 12,
            // round 2
            06, 11, 03, 07, 00, 13, 05, 10, 14, 15, 08, 12, 04, 09, 01, 02,
            // round 3
            15, 05, 01, 03, 07, 14, 06, 09, 11, 08, 12, 02, 10, 00, 04, 13,
            // round 4
            08, 06, 04, 01, 03, 11, 15, 00, 05, 12, 02, 13, 09, 07, 10, 14,
            // round 5
            12, 15, 10, 04, 01, 05, 08, 07, 06, 02, 13, 14, 00, 03, 09, 11
        };

        private static readonly int[] Shifts2 = new int[]
        {
            // round 1
            08, 09, 09, 11, 13, 15, 15, 05, 07, 07, 08, 11, 14, 14, 12, 06,
            // round 2
            09, 13, 15, 07, 12, 08, 09, 11, 07, 07, 12, 07, 06, 15, 13, 11,
            // round 3
            09, 07, 15, 11, 08, 06, 06, 14, 12, 13, 05, 14, 13, 13, 07, 05,
            // round 4
            15, 05, 08, 11, 14, 14, 06, 14, 06, 09, 12, 09, 12, 05, 15, 08,
            // round 5
            08, 05, 12, 09, 12, 05, 14, 06, 08, 13, 06, 05, 15, 13, 11, 11
        };

        #endregion

        private readonly HashState state = new HashState();

        private readonly uint[] buffer = new uint[16];

        public RIPEMD160() : base(64)
        {
            HashSizeValue = 160;
            PaddingType = PaddingType.OneZeroFillAnd8BytesMessageLengthLittleEndian;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.Initialize();
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            // Fill buffer for transformations
            LittleEndian.Copy(block, buffer);

            uint a1 = state.A, a2 = state.A;
            uint b1 = state.B, b2 = state.B;
            uint c1 = state.C, c2 = state.C;
            uint d1 = state.D, d2 = state.D;
            uint e1 = state.E, e2 = state.E;

            MDTransform1(ref a1, ref b1, ref c1, ref d1, ref e1);
            MDTransform2(ref a2, ref b2, ref c2, ref d2, ref e2);

            uint t = state.B + c1 + d2;
            state.B = state.C + d1 + e2;
            state.C = state.D + e1 + a2;
            state.D = state.E + a1 + b2;
            state.E = state.A + b1 + c2;
            state.A = t;
        }

        protected override byte[] ProcessFinalBlock()
        {
            return state.ToByteArray();
        }

        private void MDTransform1(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e)
        {
            int ii;

            // Round 1
            for (ii = 0; ii < 15; ii += 5)
            {
                a += (b ^ c ^ d);
                a += Constants1[0] + buffer[WordOrders1[ii + 00]];
                a = a << Shifts1[ii + 00] | a >> (32 - Shifts1[ii + 00]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a ^ b ^ c);
                e += Constants1[0] + buffer[WordOrders1[ii + 01]];
                e = e << Shifts1[ii + 01] | e >> (32 - Shifts1[ii + 01]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e ^ a ^ b);
                d += Constants1[0] + buffer[WordOrders1[ii + 02]];
                d = d << Shifts1[ii + 02] | d >> (32 - Shifts1[ii + 02]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d ^ e ^ a);
                c += Constants1[0] + buffer[WordOrders1[ii + 03]];
                c = c << Shifts1[ii + 03] | c >> (32 - Shifts1[ii + 03]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c ^ d ^ e);
                b += Constants1[0] + buffer[WordOrders1[ii + 04]];
                b = b << Shifts1[ii + 04] | b >> (32 - Shifts1[ii + 04]);
                b += a;

                d = d << 10 | d >> 22;
            }

            a += (b ^ c ^ d);
            a += Constants1[0] + buffer[WordOrders1[ii + 00]];
            a = a << Shifts1[ii + 00] | a >> (32 - Shifts1[ii + 00]);
            a += e;

            c = c << 10 | c >> 22;

            // Round 2
            for (ii = 16; ii < 31; ii += 5)
            {
                e += (a & b) | (~a & c);
                e += Constants1[1] + buffer[WordOrders1[ii + 00]];
                e = e << Shifts1[ii + 00] | e >> (32 - Shifts1[ii + 00]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & a) | (~e & b);
                d += Constants1[1] + buffer[WordOrders1[ii + 01]];
                d = d << Shifts1[ii + 01] | d >> (32 - Shifts1[ii + 01]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d & e) | (~d & a);
                c += Constants1[1] + buffer[WordOrders1[ii + 02]];
                c = c << Shifts1[ii + 02] | c >> (32 - Shifts1[ii + 02]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & d) | (~c & e);
                b += Constants1[1] + buffer[WordOrders1[ii + 03]];
                b = b << Shifts1[ii + 03] | b >> (32 - Shifts1[ii + 03]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & c) | (~b & d);
                a += Constants1[1] + buffer[WordOrders1[ii + 04]];
                a = a << Shifts1[ii + 04] | a >> (32 - Shifts1[ii + 04]);
                a += e;

                c = c << 10 | c >> 22;
            }

            e += (a & b) | (~a & c);
            e += Constants1[1] + buffer[WordOrders1[ii + 00]];
            e = e << Shifts1[ii + 00] | e >> (32 - Shifts1[ii + 00]);
            e += d;

            b = b << 10 | b >> 22;

            // Round 3
            for (ii = 32; ii < 47; ii += 5)
            {
                d += (e | ~a) ^ b;
                d += Constants1[2] + buffer[WordOrders1[ii + 00]];
                d = d << Shifts1[ii + 00] | d >> (32 - Shifts1[ii + 00]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d | ~e) ^ a;
                c += Constants1[2] + buffer[WordOrders1[ii + 01]];
                c = c << Shifts1[ii + 01] | c >> (32 - Shifts1[ii + 01]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c | ~d) ^ e;
                b += Constants1[2] + buffer[WordOrders1[ii + 02]];
                b = b << Shifts1[ii + 02] | b >> (32 - Shifts1[ii + 02]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b | ~c) ^ d;
                a += Constants1[2] + buffer[WordOrders1[ii + 03]];
                a = a << Shifts1[ii + 03] | a >> (32 - Shifts1[ii + 03]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a | ~b) ^ c;
                e += Constants1[2] + buffer[WordOrders1[ii + 04]];
                e = e << Shifts1[ii + 04] | e >> (32 - Shifts1[ii + 04]);
                e += d;

                b = b << 10 | b >> 22;
            }

            d += (e | ~a) ^ b;
            d += Constants1[2] + buffer[WordOrders1[ii + 00]];
            d = d << Shifts1[ii + 00] | d >> (32 - Shifts1[ii + 00]);
            d += c;

            a = a << 10 | a >> 22;

            // Round 4
            for (ii = 48; ii < 63; ii += 5)
            {
                c += (d & a) | (e & ~a);
                c += Constants1[3] + buffer[WordOrders1[ii + 00]];
                c = c << Shifts1[ii + 00] | c >> (32 - Shifts1[ii + 00]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & e) | (d & ~e);
                b += Constants1[3] + buffer[WordOrders1[ii + 01]];
                b = b << Shifts1[ii + 01] | b >> (32 - Shifts1[ii + 01]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & d) | (c & ~d);
                a += Constants1[3] + buffer[WordOrders1[ii + 02]];
                a = a << Shifts1[ii + 02] | a >> (32 - Shifts1[ii + 02]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a & c) | (b & ~c);
                e += Constants1[3] + buffer[WordOrders1[ii + 03]];
                e = e << Shifts1[ii + 03] | e >> (32 - Shifts1[ii + 03]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & b) | (a & ~b);
                d += Constants1[3] + buffer[WordOrders1[ii + 04]];
                d = d << Shifts1[ii + 04] | d >> (32 - Shifts1[ii + 04]);
                d += c;

                a = a << 10 | a >> 22;
            }

            c += (d & a) | (e & ~a);
            c += Constants1[3] + buffer[WordOrders1[ii + 00]];
            c = c << Shifts1[ii + 00] | c >> (32 - Shifts1[ii + 00]);
            c += b;

            e = e << 10 | e >> 22;

            // Round 5
            for (ii = 64; ii < 79; ii += 5)
            {
                b += c ^ (d | ~e);
                b += Constants1[4] + buffer[WordOrders1[ii + 00]];
                b = b << Shifts1[ii + 00] | b >> (32 - Shifts1[ii + 00]);
                b += a;

                d = d << 10 | d >> 22;

                a += b ^ (c | ~d);
                a += Constants1[4] + buffer[WordOrders1[ii + 01]];
                a = a << Shifts1[ii + 01] | a >> (32 - Shifts1[ii + 01]);
                a += e;

                c = c << 10 | c >> 22;

                e += a ^ (b | ~c);
                e += Constants1[4] + buffer[WordOrders1[ii + 02]];
                e = e << Shifts1[ii + 02] | e >> (32 - Shifts1[ii + 02]);
                e += d;

                b = b << 10 | b >> 22;

                d += e ^ (a | ~b);
                d += Constants1[4] + buffer[WordOrders1[ii + 03]];
                d = d << Shifts1[ii + 03] | d >> (32 - Shifts1[ii + 03]);
                d += c;

                a = a << 10 | a >> 22;

                c += d ^ (e | ~a);
                c += Constants1[4] + buffer[WordOrders1[ii + 04]];
                c = c << Shifts1[ii + 04] | c >> (32 - Shifts1[ii + 04]);
                c += b;

                e = e << 10 | e >> 22;
            }

            b += c ^ (d | ~e);
            b += Constants1[4] + buffer[WordOrders1[ii + 00]];
            b = b << Shifts1[ii + 00] | b >> (32 - Shifts1[ii + 00]);
            b += a;

            d = d << 10 | d >> 22;
        }

        private void MDTransform2(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e)
        {
            int ii = 0;
            // Round 1
            for (ii = 0; ii < 15; ii += 5)
            {
                a += b ^ (c | ~d);
                a += Constants2[0] + buffer[WordOrders2[ii + 00]];
                a = a << Shifts2[ii + 00] | a >> (32 - Shifts2[ii + 00]);
                a += e;

                c = c << 10 | c >> 22;

                e += a ^ (b | ~c);
                e += Constants2[0] + buffer[WordOrders2[ii + 01]];
                e = e << Shifts2[ii + 01] | e >> (32 - Shifts2[ii + 01]);
                e += d;

                b = b << 10 | b >> 22;

                d += e ^ (a | ~b);
                d += Constants2[0] + buffer[WordOrders2[ii + 02]];
                d = d << Shifts2[ii + 02] | d >> (32 - Shifts2[ii + 02]);
                d += c;

                a = a << 10 | a >> 22;

                c += d ^ (e | ~a);
                c += Constants2[0] + buffer[WordOrders2[ii + 03]];
                c = c << Shifts2[ii + 03] | c >> (32 - Shifts2[ii + 03]);
                c += b;

                e = e << 10 | e >> 22;

                b += c ^ (d | ~e);
                b += Constants2[0] + buffer[WordOrders2[ii + 04]];
                b = b << Shifts2[ii + 04] | b >> (32 - Shifts2[ii + 04]);
                b += a;

                d = d << 10 | d >> 22;
            }

            a += b ^ (c | ~d);
            a += Constants2[0] + buffer[WordOrders2[ii + 00]];
            a = a << Shifts2[ii + 00] | a >> (32 - Shifts2[ii + 00]);
            a += e;

            c = c << 10 | c >> 22;

            // Round 2
            for (ii = 16; ii < 31; ii += 5)
            {
                e += (a & c) | (b & ~c);
                e += Constants2[1] + buffer[WordOrders2[ii + 00]];
                e = e << Shifts2[ii + 00] | e >> (32 - Shifts2[ii + 00]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & b) | (a & ~b);
                d += Constants2[1] + buffer[WordOrders2[ii + 01]];
                d = d << Shifts2[ii + 01] | d >> (32 - Shifts2[ii + 01]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d & a) | (e & ~a);
                c += Constants2[1] + buffer[WordOrders2[ii + 02]];
                c = c << Shifts2[ii + 02] | c >> (32 - Shifts2[ii + 02]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & e) | (d & ~e);
                b += Constants2[1] + buffer[WordOrders2[ii + 03]];
                b = b << Shifts2[ii + 03] | b >> (32 - Shifts2[ii + 03]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & d) | (c & ~d);
                a += Constants2[1] + buffer[WordOrders2[ii + 04]];
                a = a << Shifts2[ii + 04] | a >> (32 - Shifts2[ii + 04]);
                a += e;

                c = c << 10 | c >> 22;
            }

            e += (a & c) | (b & ~c);
            e += Constants2[1] + buffer[WordOrders2[ii + 00]];
            e = e << Shifts2[ii + 00] | e >> (32 - Shifts2[ii + 00]);
            e += d;

            b = b << 10 | b >> 22;

            // Round 3
            for (ii = 32; ii < 47; ii += 5)
            {
                d += (e | ~a) ^ b;
                d += Constants2[2] + buffer[WordOrders2[ii + 00]];
                d = d << Shifts2[ii + 00] | d >> (32 - Shifts2[ii + 00]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d | ~e) ^ a;
                c += Constants2[2] + buffer[WordOrders2[ii + 01]];
                c = c << Shifts2[ii + 01] | c >> (32 - Shifts2[ii + 01]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c | ~d) ^ e;
                b += Constants2[2] + buffer[WordOrders2[ii + 02]];
                b = b << Shifts2[ii + 02] | b >> (32 - Shifts2[ii + 02]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b | ~c) ^ d;
                a += Constants2[2] + buffer[WordOrders2[ii + 03]];
                a = a << Shifts2[ii + 03] | a >> (32 - Shifts2[ii + 03]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a | ~b) ^ c;
                e += Constants2[2] + buffer[WordOrders2[ii + 04]];
                e = e << Shifts2[ii + 04] | e >> (32 - Shifts2[ii + 04]);
                e += d;

                b = b << 10 | b >> 22;
            }

            d += (e | ~a) ^ b;
            d += Constants2[2] + buffer[WordOrders2[ii + 00]];
            d = d << Shifts2[ii + 00] | d >> (32 - Shifts2[ii + 00]);
            d += c;

            a = a << 10 | a >> 22;

            // Round 4
            for (ii = 48; ii < 63; ii += 5)
            {
                c += (d & e) | (~d & a);
                c += Constants2[3] + buffer[WordOrders2[ii + 00]];
                c = c << Shifts2[ii + 00] | c >> (32 - Shifts2[ii + 00]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & d) | (~c & e);
                b += Constants2[3] + buffer[WordOrders2[ii + 01]];
                b = b << Shifts2[ii + 01] | b >> (32 - Shifts2[ii + 01]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & c) | (~b & d);
                a += Constants2[3] + buffer[WordOrders2[ii + 02]];
                a = a << Shifts2[ii + 02] | a >> (32 - Shifts2[ii + 02]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a & b) | (~a & c);
                e += Constants2[3] + buffer[WordOrders2[ii + 03]];
                e = e << Shifts2[ii + 03] | e >> (32 - Shifts2[ii + 03]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & a) | (~e & b);
                d += Constants2[3] + buffer[WordOrders2[ii + 04]];
                d = d << Shifts2[ii + 04] | d >> (32 - Shifts2[ii + 04]);
                d += c;

                a = a << 10 | a >> 22;
            }

            c += (d & e) | (~d & a);
            c += Constants2[3] + buffer[WordOrders2[ii + 00]];
            c = c << Shifts2[ii + 00] | c >> (32 - Shifts2[ii + 00]);
            c += b;

            e = e << 10 | e >> 22;

            // Round 5
            for (ii = 64; ii < 79; ii += 5)
            {
                b += c ^ d ^ e;
                b += Constants2[4] + buffer[WordOrders2[ii + 00]];
                b = b << Shifts2[ii + 00] | b >> (32 - Shifts2[ii + 00]);
                b += a;

                d = d << 10 | d >> 22;

                a += b ^ c ^ d;
                a += Constants2[4] + buffer[WordOrders2[ii + 01]];
                a = a << Shifts2[ii + 01] | a >> (32 - Shifts2[ii + 01]);
                a += e;

                c = c << 10 | c >> 22;

                e += a ^ b ^ c;
                e += Constants2[4] + buffer[WordOrders2[ii + 02]];
                e = e << Shifts2[ii + 02] | e >> (32 - Shifts2[ii + 02]);
                e += d;

                b = b << 10 | b >> 22;

                d += e ^ a ^ b;
                d += Constants2[4] + buffer[WordOrders2[ii + 03]];
                d = d << Shifts2[ii + 03] | d >> (32 - Shifts2[ii + 03]);
                d += c;

                a = a << 10 | a >> 22;

                c += d ^ e ^ a;
                c += Constants2[4] + buffer[WordOrders2[ii + 04]];
                c = c << Shifts2[ii + 04] | c >> (32 - Shifts2[ii + 04]);
                c += b;

                e = e << 10 | e >> 22;
            }

            b += c ^ d ^ e;
            b += Constants2[4] + buffer[WordOrders2[ii + 00]];
            b = b << Shifts2[ii + 00] | b >> (32 - Shifts2[ii + 00]);
            b += a;

            d = d << 10 | d >> 22;
        }

        private sealed class HashState
        {
            public uint A;
            public uint B;
            public uint C;
            public uint D;
            public uint E;

            public HashState()
            {
                Initialize();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Initialize()
            {
                A = 0x67452301;
                B = 0xefcdab89;
                C = 0x98badcfe;
                D = 0x10325476;
                E = 0xc3d2e1f0;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public byte[] ToByteArray()
            {
                var result = new byte[20];

                LittleEndian.Copy(A, result);
                LittleEndian.Copy(B, result.AsSpan(4));
                LittleEndian.Copy(C, result.AsSpan(8));
                LittleEndian.Copy(D, result.AsSpan(12));
                LittleEndian.Copy(E, result.AsSpan(16));

                return result;
            }
        }
    }
}
