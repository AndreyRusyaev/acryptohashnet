using System;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// </summary>
    public sealed class SHA1 : BlockHashAlgorithm
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

        private readonly BigCounter processedLength = new BigCounter(8);
        
        private readonly uint[] state = new uint[5];

        private readonly uint[] buffer = new uint[80];

        private readonly byte[] finalBlock;

        public SHA1() : base(64)
        {
            HashSizeValue = 160;

            finalBlock = new byte[BlockSize];
            InitializeState();
        }

        public override void Initialize()
        {
            base.Initialize();

            processedLength.Clear();

            Array.Clear(finalBlock, 0, finalBlock.Length);

            InitializeState();
        }

        protected override void ProcessBlock(byte[] array, int offset)
        {
            processedLength.Add(BlockSize << 3);

            // Fill buffer for transformation
            BigEndian.Copy(array.AsSpan(offset, BlockSize), buffer.AsSpan(0, 16));

            // Expand buffer
            for (int ii = 16; ii < buffer.Length; ii++)
            {
                uint x = buffer[ii - 3] ^ buffer[ii - 8] ^ buffer[ii - 14] ^ buffer[ii - 16];
                // added in sha-1
                buffer[ii] = x << 1 | x >> 31;
            }

            uint k0 = Constants[0];
            uint k1 = Constants[1];
            uint k2 = Constants[2];
            uint k3 = Constants[3];

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];

            int index = 0;
            // round 1
            for (; index < 20 && index < buffer.Length - 4; index += 5)
            {
                e += buffer[index + 0] + k0 + SHAFunctions32.Ch(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + k0 + SHAFunctions32.Ch(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + k0 + SHAFunctions32.Ch(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + k0 + SHAFunctions32.Ch(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + k0 + SHAFunctions32.Ch(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            // round 2
            for (; index < 40 && index < buffer.Length - 4; index += 5)
            {
                e += buffer[index + 0] + k1 + SHAFunctions32.Parity(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + k1 + SHAFunctions32.Parity(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + k1 + SHAFunctions32.Parity(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + k1 + SHAFunctions32.Parity(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + k1 + SHAFunctions32.Parity(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            // round 3
            for (; index < 60 && index < buffer.Length - 4; index += 5)
            {
                e += buffer[index + 0] + k2 + SHAFunctions32.Maj(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + k2 + SHAFunctions32.Maj(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + k2 + SHAFunctions32.Maj(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + k2 + SHAFunctions32.Maj(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + k2 + SHAFunctions32.Maj(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            // round 4
            for (; index < 80 && index < buffer.Length - 4; index += 5)
            {
                e += buffer[index + 0] + k3 + SHAFunctions32.Parity(b, c, d) + a.RotateLeft(5);
                b = b.RotateLeft(30);

                d += buffer[index + 1] + k3 + SHAFunctions32.Parity(a, b, c) + e.RotateLeft(5);
                a = a.RotateLeft(30);

                c += buffer[index + 2] + k3 + SHAFunctions32.Parity(e, a, b) + d.RotateLeft(5);
                e = e.RotateLeft(30);

                b += buffer[index + 3] + k3 + SHAFunctions32.Parity(d, e, a) + c.RotateLeft(5);
                d = d.RotateLeft(30);

                a += buffer[index + 4] + k3 + SHAFunctions32.Parity(c, d, e) + b.RotateLeft(5);
                c = c.RotateLeft(30);
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
        }

        protected override void ProcessFinalBlock(byte[] array, int offset, int length)
        {
            processedLength.Add(length << 3); // arg * 8

            byte[] messageLength = processedLength.GetBytes();

            Buffer.BlockCopy(array, offset, finalBlock, 0, length);

            // padding message with 100..000 bits
            finalBlock[length] = 0x80;

            int endOffset = BlockSize - 8;
            if (length >= endOffset)
            {
                ProcessBlock(finalBlock, 0);

                Array.Clear(finalBlock, 0, finalBlock.Length);
            }

            for (int ii = 0; ii < 8; ii++)
            {
                finalBlock[endOffset + ii] = messageLength[7 - ii];
            }

            // Processing of last block
            ProcessBlock(finalBlock, 0);
        }

        protected override byte[] Result
        {
            get
            {
                return BigEndian.ToByteArray(state);
            }
        }

        private void InitializeState()
        {
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;
            state[4] = 0xc3d2e1f0;
        }
    }
}