using System;

namespace Home.Andir.Cryptography
{
    public sealed class RIPEMD160 : BlockHashAlgorithm
    {
        public RIPEMD160() : base(64)
        {
            this.HashSizeValue = 160;

            this.finalBlock = new byte[BlockSize];
            this.Initialize();
        }

        private readonly IntCounter counter = new IntCounter(2);
        private readonly uint[] state = new uint[5];
        private readonly byte[] finalBlock;

        public override void Initialize()
        {
            base.Initialize();

            counter.Clear();

            Array.Clear(finalBlock, 0, finalBlock.Length);

            InitializeState();
        }

        private void InitializeState()
        {
            state[0] = 0x67452301;
            state[1] = 0xefcdab89;
            state[2] = 0x98badcfe;
            state[3] = 0x10325476;
            state[4] = 0xc3d2e1f0;
        }

        #region algorithm constant parameters 

        private static readonly uint[] constants1 = new uint[]
        {
            0x00000000,
            0x5a827999, // [2 ^ 30 * sqrt(2)]
            0x6ed9eba1, // [2 ^ 30 * sqrt(3)]
            0x8f1bbcdc, // [2 ^ 30 * sqrt(5)]
            0xa953fd4e  // [2 ^ 30 * sqrt(7)]
        };

        private static readonly uint[] wordOrders1 = new uint[]
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

        private static readonly int[] shifts1 = new int[]
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

        private static readonly uint[] constants2 = new uint[]
        {
            // root3: its root from 3 degree
            0x50a28be6, // [2 ^ 30 * root3(2)]
            0x5c4dd124, // [2 ^ 30 * root3(3)]
            0x6d703ef3, // [2 ^ 30 * root3(5)]
            0x7a6d76e9, // [2 ^ 30 * root3(7)]
            0x00000000
        };

        private static readonly uint[] wordOrders2 = new uint[]
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

        private static readonly int[] shifts2 = new int[]
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

        private uint[] buffer = new uint[16];

        protected override void ProcessBlock(byte[] array, int offset)
        {
            if (array.Length < offset + BlockSize)
                throw new ArgumentOutOfRangeException("Name: offset");

            counter.Add(BlockSize << 3);

            // Fill buffer for transformations
            Buffer.BlockCopy(array, offset, buffer, 0, BlockSize);

            uint a1 = state[0], a2 = state[0];
            uint b1 = state[1], b2 = state[1];
            uint c1 = state[2], c2 = state[2];
            uint d1 = state[3], d2 = state[3];
            uint e1 = state[4], e2 = state[4];

            MDTransform1(ref a1, ref b1, ref c1, ref d1, ref e1);
            MDTransform2(ref a2, ref b2, ref c2, ref d2, ref e2);

            uint t = state[1] + c1 + d2;
            state[1] = state[2] + d1 + e2;
            state[2] = state[3] + e1 + a2;
            state[3] = state[4] + a1 + b2;
            state[4] = state[0] + b1 + c2;
            state[0] = t;
        }

        protected override void ProcessFinalBlock(byte[] array, int offset, int length)
        {
            if (length >= BlockSize
                || length > array.Length - offset)
                throw new ArgumentOutOfRangeException("length");

            counter.Add(length << 3);

            byte[] messageLength = counter.GetBytes();

            counter.Clear();

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
                finalBlock[endOffset + ii] = messageLength[ii]; ;

            // Processing of last block
            ProcessBlock(finalBlock, 0);
        }

        protected override byte[] Result
        {
            get
            {
                // pack results
                byte[] result = new byte[20];

                Buffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
            }
        }

        private void MDTransform1(ref uint a, ref uint b, ref uint c, ref uint d, ref uint e)
        {
            int ii = 0;
            // Round 1
            for (ii = 0; ii < 15; ii += 5)
            {
                a += (b ^ c ^ d);
                a += constants1[0] + buffer[wordOrders1[ii + 00]];
                a = a << shifts1[ii + 00] | a >> (32 - shifts1[ii + 00]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a ^ b ^ c);
                e += constants1[0] + buffer[wordOrders1[ii + 01]];
                e = e << shifts1[ii + 01] | e >> (32 - shifts1[ii + 01]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e ^ a ^ b);
                d += constants1[0] + buffer[wordOrders1[ii + 02]];
                d = d << shifts1[ii + 02] | d >> (32 - shifts1[ii + 02]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d ^ e ^ a);
                c += constants1[0] + buffer[wordOrders1[ii + 03]];
                c = c << shifts1[ii + 03] | c >> (32 - shifts1[ii + 03]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c ^ d ^ e);
                b += constants1[0] + buffer[wordOrders1[ii + 04]];
                b = b << shifts1[ii + 04] | b >> (32 - shifts1[ii + 04]);
                b += a;

                d = d << 10 | d >> 22;
            }

            a += (b ^ c ^ d);
            a += constants1[0] + buffer[wordOrders1[ii + 00]];
            a = a << shifts1[ii + 00] | a >> (32 - shifts1[ii + 00]);
            a += e;

            c = c << 10 | c >> 22;

            // Round 2
            for (ii = 16; ii < 31; ii += 5)
            {
                e += (a & b) | (~a & c);
                e += constants1[1] + buffer[wordOrders1[ii + 00]];
                e = e << shifts1[ii + 00] | e >> (32 - shifts1[ii + 00]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & a) | (~e & b);
                d += constants1[1] + buffer[wordOrders1[ii + 01]];
                d = d << shifts1[ii + 01] | d >> (32 - shifts1[ii + 01]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d & e) | (~d & a);
                c += constants1[1] + buffer[wordOrders1[ii + 02]];
                c = c << shifts1[ii + 02] | c >> (32 - shifts1[ii + 02]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & d) | (~c & e);
                b += constants1[1] + buffer[wordOrders1[ii + 03]];
                b = b << shifts1[ii + 03] | b >> (32 - shifts1[ii + 03]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & c) | (~b & d);
                a += constants1[1] + buffer[wordOrders1[ii + 04]];
                a = a << shifts1[ii + 04] | a >> (32 - shifts1[ii + 04]);
                a += e;

                c = c << 10 | c >> 22;
            }

            e += (a & b) | (~a & c);
            e += constants1[1] + buffer[wordOrders1[ii + 00]];
            e = e << shifts1[ii + 00] | e >> (32 - shifts1[ii + 00]);
            e += d;

            b = b << 10 | b >> 22;

            // Round 3
            for (ii = 32; ii < 47; ii += 5)
            {
                d += (e | ~a) ^ b;
                d += constants1[2] + buffer[wordOrders1[ii + 00]];
                d = d << shifts1[ii + 00] | d >> (32 - shifts1[ii + 00]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d | ~e) ^ a;
                c += constants1[2] + buffer[wordOrders1[ii + 01]];
                c = c << shifts1[ii + 01] | c >> (32 - shifts1[ii + 01]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c | ~d) ^ e;
                b += constants1[2] + buffer[wordOrders1[ii + 02]];
                b = b << shifts1[ii + 02] | b >> (32 - shifts1[ii + 02]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b | ~c) ^ d;
                a += constants1[2] + buffer[wordOrders1[ii + 03]];
                a = a << shifts1[ii + 03] | a >> (32 - shifts1[ii + 03]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a | ~b) ^ c;
                e += constants1[2] + buffer[wordOrders1[ii + 04]];
                e = e << shifts1[ii + 04] | e >> (32 - shifts1[ii + 04]);
                e += d;

                b = b << 10 | b >> 22;
            }

            d += (e | ~a) ^ b;
            d += constants1[2] + buffer[wordOrders1[ii + 00]];
            d = d << shifts1[ii + 00] | d >> (32 - shifts1[ii + 00]);
            d += c;

            a = a << 10 | a >> 22;

            // Round 4
            for (ii = 48; ii < 63; ii += 5)
            {
                c += (d & a) | (e & ~a);
                c += constants1[3] + buffer[wordOrders1[ii + 00]];
                c = c << shifts1[ii + 00] | c >> (32 - shifts1[ii + 00]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & e) | (d & ~e);
                b += constants1[3] + buffer[wordOrders1[ii + 01]];
                b = b << shifts1[ii + 01] | b >> (32 - shifts1[ii + 01]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & d) | (c & ~d);
                a += constants1[3] + buffer[wordOrders1[ii + 02]];
                a = a << shifts1[ii + 02] | a >> (32 - shifts1[ii + 02]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a & c) | (b & ~c);
                e += constants1[3] + buffer[wordOrders1[ii + 03]];
                e = e << shifts1[ii + 03] | e >> (32 - shifts1[ii + 03]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & b) | (a & ~b);
                d += constants1[3] + buffer[wordOrders1[ii + 04]];
                d = d << shifts1[ii + 04] | d >> (32 - shifts1[ii + 04]);
                d += c;

                a = a << 10 | a >> 22;
            }

            c += (d & a) | (e & ~a);
            c += constants1[3] + buffer[wordOrders1[ii + 00]];
            c = c << shifts1[ii + 00] | c >> (32 - shifts1[ii + 00]);
            c += b;

            e = e << 10 | e >> 22;

            // Round 5
            for (ii = 64; ii < 79; ii += 5)
            {
                b += c ^ (d | ~e);
                b += constants1[4] + buffer[wordOrders1[ii + 00]];
                b = b << shifts1[ii + 00] | b >> (32 - shifts1[ii + 00]);
                b += a;

                d = d << 10 | d >> 22;

                a += b ^ (c | ~d);
                a += constants1[4] + buffer[wordOrders1[ii + 01]];
                a = a << shifts1[ii + 01] | a >> (32 - shifts1[ii + 01]);
                a += e;

                c = c << 10 | c >> 22;

                e += a ^ (b | ~c);
                e += constants1[4] + buffer[wordOrders1[ii + 02]];
                e = e << shifts1[ii + 02] | e >> (32 - shifts1[ii + 02]);
                e += d;

                b = b << 10 | b >> 22;

                d += e ^ (a | ~b);
                d += constants1[4] + buffer[wordOrders1[ii + 03]];
                d = d << shifts1[ii + 03] | d >> (32 - shifts1[ii + 03]);
                d += c;

                a = a << 10 | a >> 22;

                c += d ^ (e | ~a);
                c += constants1[4] + buffer[wordOrders1[ii + 04]];
                c = c << shifts1[ii + 04] | c >> (32 - shifts1[ii + 04]);
                c += b;

                e = e << 10 | e >> 22;
            }

            b += c ^ (d | ~e);
            b += constants1[4] + buffer[wordOrders1[ii + 00]];
            b = b << shifts1[ii + 00] | b >> (32 - shifts1[ii + 00]);
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
                a += constants2[0] + buffer[wordOrders2[ii + 00]];
                a = a << shifts2[ii + 00] | a >> (32 - shifts2[ii + 00]);
                a += e;

                c = c << 10 | c >> 22;

                e += a ^ (b | ~c);
                e += constants2[0] + buffer[wordOrders2[ii + 01]];
                e = e << shifts2[ii + 01] | e >> (32 - shifts2[ii + 01]);
                e += d;

                b = b << 10 | b >> 22;

                d += e ^ (a | ~b);
                d += constants2[0] + buffer[wordOrders2[ii + 02]];
                d = d << shifts2[ii + 02] | d >> (32 - shifts2[ii + 02]);
                d += c;

                a = a << 10 | a >> 22;

                c += d ^ (e | ~a);
                c += constants2[0] + buffer[wordOrders2[ii + 03]];
                c = c << shifts2[ii + 03] | c >> (32 - shifts2[ii + 03]);
                c += b;

                e = e << 10 | e >> 22;

                b += c ^ (d | ~e);
                b += constants2[0] + buffer[wordOrders2[ii + 04]];
                b = b << shifts2[ii + 04] | b >> (32 - shifts2[ii + 04]);
                b += a;

                d = d << 10 | d >> 22;
            }

            a += b ^ (c | ~d);
            a += constants2[0] + buffer[wordOrders2[ii + 00]];
            a = a << shifts2[ii + 00] | a >> (32 - shifts2[ii + 00]);
            a += e;

            c = c << 10 | c >> 22;

            // Round 2
            for (ii = 16; ii < 31; ii += 5)
            {
                e += (a & c) | (b & ~c);
                e += constants2[1] + buffer[wordOrders2[ii + 00]];
                e = e << shifts2[ii + 00] | e >> (32 - shifts2[ii + 00]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & b) | (a & ~b);
                d += constants2[1] + buffer[wordOrders2[ii + 01]];
                d = d << shifts2[ii + 01] | d >> (32 - shifts2[ii + 01]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d & a) | (e & ~a);
                c += constants2[1] + buffer[wordOrders2[ii + 02]];
                c = c << shifts2[ii + 02] | c >> (32 - shifts2[ii + 02]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & e) | (d & ~e);
                b += constants2[1] + buffer[wordOrders2[ii + 03]];
                b = b << shifts2[ii + 03] | b >> (32 - shifts2[ii + 03]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & d) | (c & ~d);
                a += constants2[1] + buffer[wordOrders2[ii + 04]];
                a = a << shifts2[ii + 04] | a >> (32 - shifts2[ii + 04]);
                a += e;

                c = c << 10 | c >> 22;
            }

            e += (a & c) | (b & ~c);
            e += constants2[1] + buffer[wordOrders2[ii + 00]];
            e = e << shifts2[ii + 00] | e >> (32 - shifts2[ii + 00]);
            e += d;

            b = b << 10 | b >> 22;

            // Round 3
            for (ii = 32; ii < 47; ii += 5)
            {
                d += (e | ~a) ^ b;
                d += constants2[2] + buffer[wordOrders2[ii + 00]];
                d = d << shifts2[ii + 00] | d >> (32 - shifts2[ii + 00]);
                d += c;

                a = a << 10 | a >> 22;

                c += (d | ~e) ^ a;
                c += constants2[2] + buffer[wordOrders2[ii + 01]];
                c = c << shifts2[ii + 01] | c >> (32 - shifts2[ii + 01]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c | ~d) ^ e;
                b += constants2[2] + buffer[wordOrders2[ii + 02]];
                b = b << shifts2[ii + 02] | b >> (32 - shifts2[ii + 02]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b | ~c) ^ d;
                a += constants2[2] + buffer[wordOrders2[ii + 03]];
                a = a << shifts2[ii + 03] | a >> (32 - shifts2[ii + 03]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a | ~b) ^ c;
                e += constants2[2] + buffer[wordOrders2[ii + 04]];
                e = e << shifts2[ii + 04] | e >> (32 - shifts2[ii + 04]);
                e += d;

                b = b << 10 | b >> 22;
            }

            d += (e | ~a) ^ b;
            d += constants2[2] + buffer[wordOrders2[ii + 00]];
            d = d << shifts2[ii + 00] | d >> (32 - shifts2[ii + 00]);
            d += c;

            a = a << 10 | a >> 22;

            // Round 4
            for (ii = 48; ii < 63; ii += 5)
            {
                c += (d & e) | (~d & a);
                c += constants2[3] + buffer[wordOrders2[ii + 00]];
                c = c << shifts2[ii + 00] | c >> (32 - shifts2[ii + 00]);
                c += b;

                e = e << 10 | e >> 22;

                b += (c & d) | (~c & e);
                b += constants2[3] + buffer[wordOrders2[ii + 01]];
                b = b << shifts2[ii + 01] | b >> (32 - shifts2[ii + 01]);
                b += a;

                d = d << 10 | d >> 22;

                a += (b & c) | (~b & d);
                a += constants2[3] + buffer[wordOrders2[ii + 02]];
                a = a << shifts2[ii + 02] | a >> (32 - shifts2[ii + 02]);
                a += e;

                c = c << 10 | c >> 22;

                e += (a & b) | (~a & c);
                e += constants2[3] + buffer[wordOrders2[ii + 03]];
                e = e << shifts2[ii + 03] | e >> (32 - shifts2[ii + 03]);
                e += d;

                b = b << 10 | b >> 22;

                d += (e & a) | (~e & b);
                d += constants2[3] + buffer[wordOrders2[ii + 04]];
                d = d << shifts2[ii + 04] | d >> (32 - shifts2[ii + 04]);
                d += c;

                a = a << 10 | a >> 22;
            }

            c += (d & e) | (~d & a);
            c += constants2[3] + buffer[wordOrders2[ii + 00]];
            c = c << shifts2[ii + 00] | c >> (32 - shifts2[ii + 00]);
            c += b;

            e = e << 10 | e >> 22;

            // Round 5
            for (ii = 64; ii < 79; ii += 5)
            {
                b += c ^ d ^ e;
                b += constants2[4] + buffer[wordOrders2[ii + 00]];
                b = b << shifts2[ii + 00] | b >> (32 - shifts2[ii + 00]);
                b += a;

                d = d << 10 | d >> 22;

                a += b ^ c ^ d;
                a += constants2[4] + buffer[wordOrders2[ii + 01]];
                a = a << shifts2[ii + 01] | a >> (32 - shifts2[ii + 01]);
                a += e;

                c = c << 10 | c >> 22;

                e += a ^ b ^ c;
                e += constants2[4] + buffer[wordOrders2[ii + 02]];
                e = e << shifts2[ii + 02] | e >> (32 - shifts2[ii + 02]);
                e += d;

                b = b << 10 | b >> 22;

                d += e ^ a ^ b;
                d += constants2[4] + buffer[wordOrders2[ii + 03]];
                d = d << shifts2[ii + 03] | d >> (32 - shifts2[ii + 03]);
                d += c;

                a = a << 10 | a >> 22;

                c += d ^ e ^ a;
                c += constants2[4] + buffer[wordOrders2[ii + 04]];
                c = c << shifts2[ii + 04] | c >> (32 - shifts2[ii + 04]);
                c += b;

                e = e << 10 | e >> 22;
            }

            b += c ^ d ^ e;
            b += constants2[4] + buffer[wordOrders2[ii + 00]];
            b = b << shifts2[ii + 00] | b >> (32 - shifts2[ii + 00]);
            b += a;

            d = d << 10 | d >> 22;
        }
    }
}
