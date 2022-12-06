using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// RFC1321: The MD5 Message-Digest Algorithm
    /// https://datatracker.ietf.org/doc/html/rfc1321
    /// </summary>
    public sealed class MD5 : BlockHashAlgorithm
    {
        private static readonly uint[] Constants = new uint[]
        {
            // round 1
            0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
            0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
            0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
            0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
            // round 2
            0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
            0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
            0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
            0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
            // round 3
            0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
            0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
            0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
            0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
            // round 4
            0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
            0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
            0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
            0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
        };

        private readonly HashState state = new HashState();

        private readonly uint[] buffer = new uint[16];

        public MD5() : base(64)
        {
            HashSizeValue = 128;
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
            for (int index = 0; index < 16; index += 4)
            {
                a += buffer[index + 0] + Constants[index + 0] + F(b, c, d);
                a = a.RotateLeft(7);
                a += b;

                d += buffer[index + 1] + Constants[index + 1] + F(a, b, c);
                d = d.RotateLeft(12);
                d += a;

                c += buffer[index + 2] + Constants[index + 2] + F(d, a, b);
                c = c.RotateLeft(17);
                c += d;

                b += buffer[index + 3] + Constants[index + 3] + F(c, d, a);
                b = b.RotateLeft(22);
                b += c;
            }

            // Round 2
            for (int index = 16; index < 32; index += 4)
            {
                a += buffer[((index + 0) * 5 + 1) & 0xf] + Constants[index + 0] + G(b, c, d);
                a = a.RotateLeft(5);
                a += b;

                d += buffer[((index + 1) * 5 + 1) & 0xf] + Constants[index + 1] + G(a, b, c);
                d = d.RotateLeft(9);
                d += a;

                c += buffer[((index + 2) * 5 + 1) & 0xf] + Constants[index + 2] + G(d, a, b);
                c = c.RotateLeft(14);
                c += d;

                b += buffer[((index + 3) * 5 + 1) & 0xf] + Constants[index + 3] + G(c, d, a);
                b = b.RotateLeft(20);
                b += c;
            }

            // Round 3
            for (int index = 32; index < 48; index += 4)
            {
                a += buffer[((index + 0) * 3 + 5) & 0xf] + Constants[index + 0] + H(b, c, d);
                a = a.RotateLeft(4);
                a += b;

                d += buffer[((index + 1) * 3 + 5) & 0xf] + Constants[index + 1] + H(a, b, c);
                d = d.RotateLeft(11);
                d += a;

                c += buffer[((index + 2) * 3 + 5) & 0xf] + Constants[index + 2] + H(d, a, b);
                c = c.RotateLeft(16);
                c += d;

                b += buffer[((index + 3) * 3 + 5) & 0xf] + Constants[index + 3] + H(c, d, a);
                b = b.RotateLeft(23);
                b += c;
            }

            // Round 4
            for (int index = 48; index < 64; index += 4)
            {
                a += buffer[((index + 0) * 7 + 0) & 0xf] + Constants[index + 0] + I(b, c, d);
                a = a.RotateLeft(6);
                a += b;

                d += buffer[((index + 1) * 7 + 0) & 0xf] + Constants[index + 1] + I(a, b, c);
                d = d.RotateLeft(10);
                d += a;

                c += buffer[((index + 2) * 7 + 0) & 0xf] + Constants[index + 2] + I(d, a, b);
                c = c.RotateLeft(15);
                c += d;

                b += buffer[((index + 3) * 7 + 0) & 0xf] + Constants[index + 3] + I(c, d, a);
                b = b.RotateLeft(21);
                b += c;
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

        protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var paddingBlocks = lastBlock.Length + 8 > BlockSizeValue ? 2 : 1;
            var padding = new byte[paddingBlocks * BlockSizeValue];

            lastBlock.CopyTo(padding);

            padding[lastBlock.Length] = 0x80;

            byte[] messageLengthInBits = (messageLength << 3).ToByteArray();
            if (messageLengthInBits.Length > 8)
            {
                var supportedLength = BigInteger.Pow(2, 8 << 3) - 1;
                throw new InvalidOperationException(
                    $"Message is too long for this hash algorithm. Actual: {messageLength}, Max supported: {supportedLength} bytes.");
            }

            var endOffset = padding.Length - 8;
            for (int ii = 0; ii < messageLengthInBits.Length; ii++)
            {
                padding[endOffset + ii] = messageLengthInBits[ii];
            }

            return padding;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint F(uint x, uint y, uint z) => (x & y) | (~x & z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint G(uint x, uint y, uint z) => (x & z) | (y & ~z);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint H(uint x, uint y, uint z) => x ^ y ^ z;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint I(uint x, uint y, uint z) => y ^ (x | ~z);

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