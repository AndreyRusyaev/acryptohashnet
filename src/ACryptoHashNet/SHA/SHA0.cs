using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// </summary>
    public sealed class SHA0 : BlockHashAlgorithm
    {
        private static readonly uint[] Constants = new uint[4]
        {
            // round 1
            0x5a827999, // [2 ^ 30 * sqrt(2)]
            // round 2
            0x6ed9eba1, // [2 ^ 30 * sqrt(3)]
            // round 3
            0x8f1bbcdc, // [2 ^ 30 * sqrt(5)]
            // round 4
            0xca62c1d6  // [2 ^ 30 * sqrt(10)]
        };

        private readonly HashState state = new HashState();

        private readonly uint[] buffer = new uint[80];

        public SHA0() : base(64)
        {
            HashSizeValue = 160;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.Initialize();
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            // Fill buffer for transformations
            BigEndian.Copy(block, buffer.AsSpan(0, 16));

            for (int ii = 16; ii < buffer.Length; ii++)
            {
                buffer[ii] = buffer[ii - 3] ^ buffer[ii - 8] ^ buffer[ii - 14] ^ buffer[ii - 16];
            }

            uint a = state.A;
            uint b = state.B;
            uint c = state.C;
            uint d = state.D;
            uint e = state.E;
            
            // round 1
            for (int index = 0; index < 20 && index <= buffer.Length - 5; index += 5)
            {
                e += buffer[index + 0] + Constants[0] + SHAFunctions32.Ch(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + Constants[0] + SHAFunctions32.Ch(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + Constants[0] + SHAFunctions32.Ch(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + Constants[0] + SHAFunctions32.Ch(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + Constants[0] + SHAFunctions32.Ch(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            // round 2
            for (int index = 20; index < 40 && index <= buffer.Length - 5; index += 5)
            {
                e += buffer[index + 0] + Constants[1] + SHAFunctions32.Parity(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + Constants[1] + SHAFunctions32.Parity(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + Constants[1] + SHAFunctions32.Parity(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + Constants[1] + SHAFunctions32.Parity(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + Constants[1] + SHAFunctions32.Parity(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            // round 3
            for (int index = 40; index < 60 && index <= buffer.Length - 5; index += 5)
            {
                e += buffer[index + 0] + Constants[2] + SHAFunctions32.Maj(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + Constants[2] + SHAFunctions32.Maj(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + Constants[2] + SHAFunctions32.Maj(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + Constants[2] + SHAFunctions32.Maj(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + Constants[2] + SHAFunctions32.Maj(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            // round 4
            for (int index = 60; index < 80 && index <= buffer.Length - 5; index += 5)
            {
                e += buffer[index + 0] + Constants[3] + SHAFunctions32.Parity(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + Constants[3] + SHAFunctions32.Parity(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + Constants[3] + SHAFunctions32.Parity(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + Constants[3] + SHAFunctions32.Parity(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + Constants[3] + SHAFunctions32.Parity(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            state.A += a;
            state.B += b;
            state.C += c;
            state.D += d;
            state.E += e;
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
            for (int ii = 8 - messageLengthInBits.Length; ii < 8; ii++)
            {
                padding[endOffset + ii] = messageLengthInBits[7 - ii];
            }

            return padding;
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

                BigEndian.Copy(A, result);
                BigEndian.Copy(B, result.AsSpan(4));
                BigEndian.Copy(C, result.AsSpan(8));
                BigEndian.Copy(D, result.AsSpan(12));
                BigEndian.Copy(E, result.AsSpan(16));

                return result;
            }
        }
    }
}