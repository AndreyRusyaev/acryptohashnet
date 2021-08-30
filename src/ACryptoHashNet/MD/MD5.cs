using System;

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

        private readonly BigCounter processedLength = new BigCounter(8);

        private readonly uint[] state = new uint[4];

        private readonly uint[] buffer = new uint[16];

        private readonly byte[] finalBlock;

        public MD5() : base(64)
        {
            HashSizeValue = 128;

            finalBlock = new byte[BlockSize];
            Initialize();
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
            processedLength.Add(BlockSize << 3); // * 8

            // Fill buffer for transformations
            Buffer.BlockCopy(array, offset, buffer, 0, BlockSize);

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];

            // Round 1
            for (int ii = 0; ii < 16; ii += 4)
            {
                a += buffer[ii + 0] + Constants[ii + 0];
                a += (b & c) | (~b & d);
                a = a << 7 | a >> 25;
                a += b;

                d += buffer[ii + 1] + Constants[ii + 1];
                d += (a & b) | (~a & c);
                d = d << 12 | d >> 20;
                d += a;

                c += buffer[ii + 2] + Constants[ii + 2];
                c += (d & a) | (~d & b);
                c = c << 17 | c >> 15;
                c += d;

                b += buffer[ii + 3] + Constants[ii + 3];
                b += (c & d) | (~c & a);
                b = b << 22 | b >> 10;
                b += c;
            }

            // Round 2
            for (int ii = 16; ii < 32; ii += 4)
            {
                a += buffer[((ii + 0) * 5 + 1) & 0xf] + Constants[ii + 0];
                a += (b & d) | (c & ~d);
                a = a << 5 | a >> 27;
                a += b;

                d += buffer[((ii + 1) * 5 + 1) & 0xf] + Constants[ii + 1];
                d += (a & c) | (b & ~c);
                d = d << 9 | d >> 23;
                d += a;

                c += buffer[((ii + 2) * 5 + 1) & 0xf] + Constants[ii + 2];
                c += (d & b) | (a & ~b);
                c = c << 14 | c >> 18;
                c += d;

                b += buffer[((ii + 3) * 5 + 1) & 0xf] + Constants[ii + 3];
                b += (c & a) | (d & ~a);
                b = b << 20 | b >> 12;
                b += c;
            }

            // Round 3
            for (int ii = 32; ii < 48; ii += 4)
            {
                a += buffer[((ii + 0) * 3 + 5) & 0xf] + Constants[ii + 0];
                a += b ^ c ^ d;
                a = a << 4 | a >> 28;
                a += b;

                d += buffer[((ii + 1) * 3 + 5) & 0xf] + Constants[ii + 1];
                d += a ^ b ^ c;
                d = d << 11 | d >> 21;
                d += a;

                c += buffer[((ii + 2) * 3 + 5) & 0xf] + Constants[ii + 2];
                c += d ^ a ^ b;
                c = c << 16 | c >> 16;
                c += d;

                b += buffer[((ii + 3) * 3 + 5) & 0xf] + Constants[ii + 3];
                b += c ^ d ^ a;
                b = b << 23 | b >> 9;
                b += c;
            }

            // Round 4
            for (int ii = 48; ii < 64; ii += 4)
            {
                a += buffer[((ii + 0) * 7 + 0) & 0xf] + Constants[ii + 0];
                a += c ^ (b | ~d);
                a = a << 6 | a >> 26;
                a += b;

                d += buffer[((ii + 1) * 7 + 0) & 0xf] + Constants[ii + 1];
                d += b ^ (a | ~c);
                d = d << 10 | d >> 22;
                d += a;

                c += buffer[((ii + 2) * 7 + 0) & 0xf] + Constants[ii + 2];
                c += a ^ (d | ~b);
                c = c << 15 | c >> 17;
                c += d;

                b += buffer[((ii + 3) * 7 + 0) & 0xf] + Constants[ii + 3];
                b += d ^ (c | ~a);
                b = b << 21 | b >> 11;
                b += c;
            }

            // The end
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
        }

        protected override void ProcessFinalBlock(byte[] array, int offset, int length)
        {
            processedLength.Add(length << 3); // * 8

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
                finalBlock[endOffset + ii] = messageLength[ii];
            }

            // Processing of last block
            ProcessBlock(finalBlock, 0);
        }

        protected override byte[] Result
        {
            get
            {
                byte[] result = new byte[16];

                Buffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
            }
        }

        private void InitializeState()
        {
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;
        }
    }
}