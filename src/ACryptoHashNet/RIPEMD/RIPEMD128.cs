using System;

namespace Home.Andir.Cryptography
{
    public sealed class RIPEMD128 : BlockHashAlgorithm
    {
        public RIPEMD128() : base(64)
        {
            this.HashSizeValue = 128;

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
        }

        #region algorithm constant parameters

        private static readonly uint[] constants1 = new uint[]
        {
            0x00000000,
            0x5a827999, // [2 ^ 30 * sqrt(2)]
            0x6ed9eba1, // [2 ^ 30 * sqrt(3)]
            0x8f1bbcdc  // [2 ^ 30 * sqrt(5)]
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
            01, 09, 11, 10, 00, 08, 12, 04, 13, 03, 07, 15, 14, 05, 06, 02
        };

        private static readonly int[] _shifts1 = new int[]
        {
            // round 1
            11, 14, 15, 12, 05, 08, 07, 09, 11, 13, 14, 15, 06, 07, 09, 08,
            // round 2
            07, 06, 08, 13, 11, 09, 07, 15, 07, 12, 15, 09, 11, 07, 13, 12,
            // round 3
            11, 13, 06, 07, 14, 09, 13, 15, 14, 08, 13, 06, 05, 12, 07, 05,
            // round 4
            11, 12, 14, 15, 14, 15, 09, 08, 09, 14, 05, 06, 08, 06, 05, 12
        };

        private static readonly uint[] constants2 = new uint[]
        {
            // root3 is a cube root
            0x50a28be6, // [2 ^ 30 * root3(2)]
            0x5c4dd124, // [2 ^ 30 * root3(3)]
            0x6d703ef3, // [2 ^ 30 * root3(5)]
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
            08, 06, 04, 01, 03, 11, 15, 00, 05, 12, 02, 13, 09, 07, 10, 14
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
            15, 05, 08, 11, 14, 14, 06, 14, 06, 09, 12, 09, 12, 05, 15, 08
        };

        #endregion

        private uint[] buffer = new uint[16];

        protected override void ProcessBlock(byte[] array, int offset)
        {
            if (array.Length < offset + BlockSize)
                throw new ArgumentOutOfRangeException("offset");

            counter.Add(BlockSize << 3);

            // Fill buffer for transformations
            Buffer.BlockCopy(array, offset, buffer, 0, BlockSize);

            uint a1 = state[0], a2 = state[0];
            uint b1 = state[1], b2 = state[1];
            uint c1 = state[2], c2 = state[2];
            uint d1 = state[3], d2 = state[3];

            MDTransform1(ref a1, ref b1, ref c1, ref d1);
            MDTransform2(ref a2, ref b2, ref c2, ref d2);

            uint t = state[1] + c1 + d2;
            state[1] = state[2] + d1 + a2;
            state[2] = state[3] + a1 + b2;
            state[3] = state[0] + b1 + c2;
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
                finalBlock[endOffset + ii] = messageLength[ii];

            // Processing of last block
            ProcessBlock(finalBlock, 0);
        }

        protected override byte[] Result
        {
            get
            {
                // pack results
                byte[] result = new byte[16];

                Buffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
            }
        }

        private void MDTransform1(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            // Round 1
            for (int ii = 0; ii < 16; ii += 4)
            {
                a += (b ^ c ^ d);
                a += constants1[0] + buffer[wordOrders1[ii + 00]];
                a = a << _shifts1[ii + 00] | a >> (32 - _shifts1[ii + 00]);

                d += (a ^ b ^ c);
                d += constants1[0] + buffer[wordOrders1[ii + 01]];
                d = d << _shifts1[ii + 01] | d >> (32 - _shifts1[ii + 01]);

                c += (d ^ a ^ b);
                c += constants1[0] + buffer[wordOrders1[ii + 02]];
                c = c << _shifts1[ii + 02] | c >> (32 - _shifts1[ii + 02]);

                b += (c ^ d ^ a);
                b += constants1[0] + buffer[wordOrders1[ii + 03]];
                b = b << _shifts1[ii + 03] | b >> (32 - _shifts1[ii + 03]);
            }

            // Round 2
            for (int ii = 16; ii < 32; ii += 4)
            {
                a += (b & c) | (~b & d);
                a += constants1[1] + buffer[wordOrders1[ii + 00]];
                a = a << _shifts1[ii + 00] | a >> (32 - _shifts1[ii + 00]);

                d += (a & b) | (~a & c);
                d += constants1[1] + buffer[wordOrders1[ii + 01]];
                d = d << _shifts1[ii + 01] | d >> (32 - _shifts1[ii + 01]);

                c += (d & a) | (~d & b);
                c += constants1[1] + buffer[wordOrders1[ii + 02]];
                c = c << _shifts1[ii + 02] | c >> (32 - _shifts1[ii + 02]);

                b += (c & d) | (~c & a);
                b += constants1[1] + buffer[wordOrders1[ii + 03]];
                b = b << _shifts1[ii + 03] | b >> (32 - _shifts1[ii + 03]);
            }

            // Round 3
            for (int ii = 32; ii < 48; ii += 4)
            {
                a += (b | ~c) ^ d;
                a += constants1[2] + buffer[wordOrders1[ii + 00]];
                a = a << _shifts1[ii + 00] | a >> (32 - _shifts1[ii + 00]);

                d += (a | ~b) ^ c;
                d += constants1[2] + buffer[wordOrders1[ii + 01]];
                d = d << _shifts1[ii + 01] | d >> (32 - _shifts1[ii + 01]);

                c += (d | ~a) ^ b;
                c += constants1[2] + buffer[wordOrders1[ii + 02]];
                c = c << _shifts1[ii + 02] | c >> (32 - _shifts1[ii + 02]);

                b += (c | ~d) ^ a;
                b += constants1[2] + buffer[wordOrders1[ii + 03]];
                b = b << _shifts1[ii + 03] | b >> (32 - _shifts1[ii + 03]);
            }

            // Round 4
            for (int ii = 48; ii < 64; ii += 4)
            {
                a += (b & d) | (c & ~d);
                a += constants1[3] + buffer[wordOrders1[ii + 00]];
                a = a << _shifts1[ii + 00] | a >> (32 - _shifts1[ii + 00]);

                d += (a & c) | (b & ~c);
                d += constants1[3] + buffer[wordOrders1[ii + 01]];
                d = d << _shifts1[ii + 01] | d >> (32 - _shifts1[ii + 01]);

                c += (d & b) | (a & ~b);
                c += constants1[3] + buffer[wordOrders1[ii + 02]];
                c = c << _shifts1[ii + 02] | c >> (32 - _shifts1[ii + 02]);

                b += (c & a) | (d & ~a);
                b += constants1[3] + buffer[wordOrders1[ii + 03]];
                b = b << _shifts1[ii + 03] | b >> (32 - _shifts1[ii + 03]);
            }
        }

        private void MDTransform2(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            // Round 1
            for (int ii = 0; ii < 16; ii += 4)
            {
                a += (b & d) | (c & ~d);
                a += constants2[0] + buffer[wordOrders2[ii + 00]];
                a = a << shifts2[ii + 00] | a >> (32 - shifts2[ii + 00]);

                d += (a & c) | (b & ~c);
                d += constants2[0] + buffer[wordOrders2[ii + 01]];
                d = d << shifts2[ii + 01] | d >> (32 - shifts2[ii + 01]);

                c += (d & b) | (a & ~b);
                c += constants2[0] + buffer[wordOrders2[ii + 02]];
                c = c << shifts2[ii + 02] | c >> (32 - shifts2[ii + 02]);

                b += (c & a) | (d & ~a);
                b += constants2[0] + buffer[wordOrders2[ii + 03]];
                b = b << shifts2[ii + 03] | b >> (32 - shifts2[ii + 03]);
            }

            // Round 2
            for (int ii = 16; ii < 32; ii += 4)
            {
                a += (b | ~c) ^ d;
                a += constants2[1] + buffer[wordOrders2[ii + 00]];
                a = a << shifts2[ii + 00] | a >> (32 - shifts2[ii + 00]);

                d += (a | ~b) ^ c;
                d += constants2[1] + buffer[wordOrders2[ii + 01]];
                d = d << shifts2[ii + 01] | d >> (32 - shifts2[ii + 01]);

                c += (d | ~a) ^ b;
                c += constants2[1] + buffer[wordOrders2[ii + 02]];
                c = c << shifts2[ii + 02] | c >> (32 - shifts2[ii + 02]);

                b += (c | ~d) ^ a;
                b += constants2[1] + buffer[wordOrders2[ii + 03]];
                b = b << shifts2[ii + 03] | b >> (32 - shifts2[ii + 03]);
            }

            // Round 3
            for (int ii = 32; ii < 48; ii += 4)
            {
                a += (b & c) | (~b & d);
                a += constants2[2] + buffer[wordOrders2[ii + 00]];
                a = a << shifts2[ii + 00] | a >> (32 - shifts2[ii + 00]);

                d += (a & b) | (~a & c);
                d += constants2[2] + buffer[wordOrders2[ii + 01]];
                d = d << shifts2[ii + 01] | d >> (32 - shifts2[ii + 01]);

                c += (d & a) | (~d & b);
                c += constants2[2] + buffer[wordOrders2[ii + 02]];
                c = c << shifts2[ii + 02] | c >> (32 - shifts2[ii + 02]);

                b += (c & d) | (~c & a);
                b += constants2[2] + buffer[wordOrders2[ii + 03]];
                b = b << shifts2[ii + 03] | b >> (32 - shifts2[ii + 03]);
            }

            // Round 4
            for (int ii = 48; ii < 64; ii += 4)
            {
                a += (b ^ c ^ d);
                a += constants2[3] + buffer[wordOrders2[ii + 00]];
                a = a << shifts2[ii + 00] | a >> (32 - shifts2[ii + 00]);

                d += (a ^ b ^ c);
                d += constants2[3] + buffer[wordOrders2[ii + 01]];
                d = d << shifts2[ii + 01] | d >> (32 - shifts2[ii + 01]);

                c += (d ^ a ^ b);
                c += constants2[3] + buffer[wordOrders2[ii + 02]];
                c = c << shifts2[ii + 02] | c >> (32 - shifts2[ii + 02]);

                b += (c ^ d ^ a);
                b += constants2[3] + buffer[wordOrders2[ii + 03]];
                b = b << shifts2[ii + 03] | b >> (32 - shifts2[ii + 03]);
            }
        }
    }
}
