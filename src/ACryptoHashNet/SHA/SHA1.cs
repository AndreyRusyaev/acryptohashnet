using System;

namespace Home.Andir.Cryptography
{
    public sealed class SHA1 : BlockHashAlgorithm
    {
        private static readonly uint[] Constants = new uint[4]
        {
            // round 1
            0x5a827999,
            // round 2
            0x6ed9eba1,
            // round 3
            0x8f1bbcdc,
            // round 4
            0xca62c1d6
        };

        private readonly BigCounter processedLength = new BigCounter(8);
        
        private readonly uint[] state = new uint[5];

        private readonly uint[] buffer = new uint[80];

        private readonly byte[] finalBlock;

        public SHA1() : base(64)
        {
            HashSizeValue = 160;

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
            processedLength.Add(BlockSize << 3);

            // Fill buffer for transformations
            BigEndianBuffer.BlockCopy(array, offset, buffer, 0, BlockSize);

            for (int ii = 16; ii < 80; ii++)
            {
                buffer[ii] = buffer[ii - 3] ^ buffer[ii - 8] ^ buffer[ii - 14] ^ buffer[ii - 16];
                // added in sha-1
                buffer[ii] = buffer[ii] << 1 | buffer[ii] >> 31;
            }

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];

            // round 1
            for (int ii = 0; ii < 20; ii += 5)
            {
                e += buffer[ii + 0] + Constants[0];
                e += (b & c) ^ (~b & d);
                e += a << 5 | a >> 27;
                b = b << 30 | b >> 2;

                d += buffer[ii + 1] + Constants[0];
                d += (a & b) ^ (~a & c);
                d += e << 5 | e >> 27;
                a = a << 30 | a >> 2;

                c += buffer[ii + 2] + Constants[0];
                c += (e & a) ^ (~e & b);
                c += d << 5 | d >> 27;
                e = e << 30 | e >> 2;

                b += buffer[ii + 3] + Constants[0];
                b += (d & e) ^ (~d & a);
                b += c << 5 | c >> 27;
                d = d << 30 | d >> 2;

                a += buffer[ii + 4] + Constants[0];
                a += (c & d) ^ (~c & e);
                a += b << 5 | b >> 27;
                c = c << 30 | c >> 2;
            }

            // round 2
            for (int ii = 20; ii < 40; ii += 5)
            {
                e += buffer[ii + 0] + Constants[1];
                e += b ^ c ^ d;
                e += a << 5 | a >> 27;
                b = b << 30 | b >> 2;

                d += buffer[ii + 1] + Constants[1];
                d += a ^ b ^ c;
                d += e << 5 | e >> 27;
                a = a << 30 | a >> 2;

                c += buffer[ii + 2] + Constants[1];
                c += e ^ a ^ b;
                c += d << 5 | d >> 27;
                e = e << 30 | e >> 2;

                b += buffer[ii + 3] + Constants[1];
                b += d ^ e ^ a;
                b += c << 5 | c >> 27;
                d = d << 30 | d >> 2;

                a += buffer[ii + 4] + Constants[1];
                a += c ^ d ^ e;
                a += b << 5 | b >> 27;
                c = c << 30 | c >> 2;
            }

            // round 3
            for (int ii = 40; ii < 60; ii += 5)
            {
                e += buffer[ii + 0] + Constants[2];
                e += (b & c) ^ (b & d) ^ (c & d);
                e += a << 5 | a >> 27;
                b = b << 30 | b >> 2;

                d += buffer[ii + 1] + Constants[2];
                d += (a & b) ^ (a & c) ^ (b & c);
                d += e << 5 | e >> 27;
                a = a << 30 | a >> 2;

                c += buffer[ii + 2] + Constants[2];
                c += (e & a) ^ (e & b) ^ (a & b);
                c += d << 5 | d >> 27;
                e = e << 30 | e >> 2;

                b += buffer[ii + 3] + Constants[2];
                b += (d & e) ^ (d & a) ^ (e & a);
                b += c << 5 | c >> 27;
                d = d << 30 | d >> 2;

                a += buffer[ii + 4] + Constants[2];
                a += (c & d) ^ (c & e) ^ (d & e);
                a += b << 5 | b >> 27;
                c = c << 30 | c >> 2;
            }

            // round 4
            for (int ii = 60; ii < 80; ii += 5)
            {
                e += buffer[ii + 0] + Constants[3];
                e += b ^ c ^ d;
                e += a << 5 | a >> 27;
                b = b << 30 | b >> 2;

                d += buffer[ii + 1] + Constants[3];
                d += a ^ b ^ c;
                d += e << 5 | e >> 27;
                a = a << 30 | a >> 2;

                c += buffer[ii + 2] + Constants[3];
                c += e ^ a ^ b;
                c += d << 5 | d >> 27;
                e = e << 30 | e >> 2;

                b += buffer[ii + 3] + Constants[3];
                b += d ^ e ^ a;
                b += c << 5 | c >> 27;
                d = d << 30 | d >> 2;

                a += buffer[ii + 4] + Constants[3];
                a += c ^ d ^ e;
                a += b << 5 | b >> 27;
                c = c << 30 | c >> 2;
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
                byte[] result = new byte[20];

                BigEndianBuffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
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