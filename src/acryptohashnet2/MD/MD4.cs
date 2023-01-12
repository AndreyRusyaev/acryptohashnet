using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// RFC1320: The MD4 Message-Digest Algorithm
    /// https://datatracker.ietf.org/doc/html/rfc1320
    /// </summary>
    public sealed class MD4 : BlockHashAlgorithm
    {
        private static readonly uint[] Constants = new uint[]
        {
            0x00000000,
            0x5a827999, // [2 ^ 30 * sqrt(2)]
            0x6ed9eba1, // [2 ^ 30 * sqrt(3)]
        };

        private readonly HashState state = new HashState();

        private readonly uint[] buffer = new uint[16];

        public MD4() : base(64)
        {
            HashSizeValue = 128;
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

            uint a = state.A;
            uint b = state.B;
            uint c = state.C;
            uint d = state.D;

            // Round 1
            for (int ii = 0; ii < 16; ii += 4)
            {
                a += buffer[ii + 0] + Constants[0] + F(b, c, d);
                a = a.RotateLeft(3);

                d += buffer[ii + 1] + Constants[0] + F(a, b, c);
                d = d.RotateLeft(7);

                c += buffer[ii + 2] + Constants[0] + F(d, a, b);
                c = c.RotateLeft(11);

                b += buffer[ii + 3] + Constants[0] + F(c, d, a);
                b = b.RotateLeft(19);
            }

            // Round 2
            for (int ii = 16, jj = 0; ii < 32; ii += 4, jj++)
            {
                a += buffer[jj + 00] + Constants[1] + G(b, c, d);
                a = a.RotateLeft(3);

                d += buffer[jj + 04] + Constants[1] + G(a, b, c);
                d = d.RotateLeft(5);

                c += buffer[jj + 08] + Constants[1] + G(d, a, b);
                c = c.RotateLeft(9);

                b += buffer[jj + 12] + Constants[1] + G(c, d, a);
                b = b.RotateLeft(13);
            }

            // Round 3
            for (int ii = 32, jj = 0; ii < 48; ii += 4, jj++)
            {
                int index = (jj << 1) + -3 * (jj >> 1); // jj * 2 + (jj / 2) * (-3);

                a += buffer[index + 00] + Constants[2] + H(b, c, d);
                a = a.RotateLeft(3);

                d += buffer[index + 08] + Constants[2] + H(a, b, c);
                d = d.RotateLeft(9);

                c += buffer[index + 04] + Constants[2] + H(d, a, b);
                c = c.RotateLeft(11);

                b += buffer[index + 12] + Constants[2] + H(c, d, a);
                b = b.RotateLeft(15);
            }

            state.A += a;
            state.B += b;
            state.C += c;
            state.D += d;
        }

        protected override byte[] ProcessFinalBlock()
        {
            return state.ToByteArray();
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint G(uint x, uint y, uint z) => (x & y) | (x & z) | (y & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint H(uint x, uint y, uint z) => x ^ y ^ z;

        private sealed class HashState
        {
            public uint A;
            public uint B;
            public uint C;
            public uint D;

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
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public byte[] ToByteArray()
            {
                var result = new byte[16];

                LittleEndian.Copy(A, result);
                LittleEndian.Copy(B, result.AsSpan(4));
                LittleEndian.Copy(C, result.AsSpan(8));
                LittleEndian.Copy(D, result.AsSpan(12));

                return result;
            }
        }
    }
}
