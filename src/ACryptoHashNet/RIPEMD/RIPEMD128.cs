﻿using System;

namespace Home.Andir.Cryptography
{
    public sealed class RIPEMD128 : BlockHashAlgorithm
    {
        #region algorithm constant parameters

        private static readonly uint[] Constants1 = new uint[]
        {
            0x00000000,
            0x5a827999, // [2 ^ 30 * sqrt(2)]
            0x6ed9eba1, // [2 ^ 30 * sqrt(3)]
            0x8f1bbcdc  // [2 ^ 30 * sqrt(5)]
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
            01, 09, 11, 10, 00, 08, 12, 04, 13, 03, 07, 15, 14, 05, 06, 02
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
            11, 12, 14, 15, 14, 15, 09, 08, 09, 14, 05, 06, 08, 06, 05, 12
        };

        private static readonly uint[] Constants2 = new uint[]
        {
            // root3 is a cube root
            0x50a28be6, // [2 ^ 30 * root3(2)]
            0x5c4dd124, // [2 ^ 30 * root3(3)]
            0x6d703ef3, // [2 ^ 30 * root3(5)]
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
            08, 06, 04, 01, 03, 11, 15, 00, 05, 12, 02, 13, 09, 07, 10, 14
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
            15, 05, 08, 11, 14, 14, 06, 14, 06, 09, 12, 09, 12, 05, 15, 08
        };

        #endregion

        private readonly BigCounter processedLength = new BigCounter(8);

        private readonly uint[] state = new uint[5];

        private readonly uint[] buffer = new uint[16];

        private readonly byte[] finalBlock;

        public RIPEMD128() : base(64)
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

        private void MDTransform1(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            // Round 1
            for (int ii = 0; ii < 16; ii += 4)
            {
                a += (b ^ c ^ d);
                a += Constants1[0] + buffer[WordOrders1[ii + 00]];
                a = a << Shifts1[ii + 00] | a >> (32 - Shifts1[ii + 00]);

                d += (a ^ b ^ c);
                d += Constants1[0] + buffer[WordOrders1[ii + 01]];
                d = d << Shifts1[ii + 01] | d >> (32 - Shifts1[ii + 01]);

                c += (d ^ a ^ b);
                c += Constants1[0] + buffer[WordOrders1[ii + 02]];
                c = c << Shifts1[ii + 02] | c >> (32 - Shifts1[ii + 02]);

                b += (c ^ d ^ a);
                b += Constants1[0] + buffer[WordOrders1[ii + 03]];
                b = b << Shifts1[ii + 03] | b >> (32 - Shifts1[ii + 03]);
            }

            // Round 2
            for (int ii = 16; ii < 32; ii += 4)
            {
                a += (b & c) | (~b & d);
                a += Constants1[1] + buffer[WordOrders1[ii + 00]];
                a = a << Shifts1[ii + 00] | a >> (32 - Shifts1[ii + 00]);

                d += (a & b) | (~a & c);
                d += Constants1[1] + buffer[WordOrders1[ii + 01]];
                d = d << Shifts1[ii + 01] | d >> (32 - Shifts1[ii + 01]);

                c += (d & a) | (~d & b);
                c += Constants1[1] + buffer[WordOrders1[ii + 02]];
                c = c << Shifts1[ii + 02] | c >> (32 - Shifts1[ii + 02]);

                b += (c & d) | (~c & a);
                b += Constants1[1] + buffer[WordOrders1[ii + 03]];
                b = b << Shifts1[ii + 03] | b >> (32 - Shifts1[ii + 03]);
            }

            // Round 3
            for (int ii = 32; ii < 48; ii += 4)
            {
                a += (b | ~c) ^ d;
                a += Constants1[2] + buffer[WordOrders1[ii + 00]];
                a = a << Shifts1[ii + 00] | a >> (32 - Shifts1[ii + 00]);

                d += (a | ~b) ^ c;
                d += Constants1[2] + buffer[WordOrders1[ii + 01]];
                d = d << Shifts1[ii + 01] | d >> (32 - Shifts1[ii + 01]);

                c += (d | ~a) ^ b;
                c += Constants1[2] + buffer[WordOrders1[ii + 02]];
                c = c << Shifts1[ii + 02] | c >> (32 - Shifts1[ii + 02]);

                b += (c | ~d) ^ a;
                b += Constants1[2] + buffer[WordOrders1[ii + 03]];
                b = b << Shifts1[ii + 03] | b >> (32 - Shifts1[ii + 03]);
            }

            // Round 4
            for (int ii = 48; ii < 64; ii += 4)
            {
                a += (b & d) | (c & ~d);
                a += Constants1[3] + buffer[WordOrders1[ii + 00]];
                a = a << Shifts1[ii + 00] | a >> (32 - Shifts1[ii + 00]);

                d += (a & c) | (b & ~c);
                d += Constants1[3] + buffer[WordOrders1[ii + 01]];
                d = d << Shifts1[ii + 01] | d >> (32 - Shifts1[ii + 01]);

                c += (d & b) | (a & ~b);
                c += Constants1[3] + buffer[WordOrders1[ii + 02]];
                c = c << Shifts1[ii + 02] | c >> (32 - Shifts1[ii + 02]);

                b += (c & a) | (d & ~a);
                b += Constants1[3] + buffer[WordOrders1[ii + 03]];
                b = b << Shifts1[ii + 03] | b >> (32 - Shifts1[ii + 03]);
            }
        }

        private void MDTransform2(ref uint a, ref uint b, ref uint c, ref uint d)
        {
            // Round 1
            for (int ii = 0; ii < 16; ii += 4)
            {
                a += (b & d) | (c & ~d);
                a += Constants2[0] + buffer[WordOrders2[ii + 00]];
                a = a << Shifts2[ii + 00] | a >> (32 - Shifts2[ii + 00]);

                d += (a & c) | (b & ~c);
                d += Constants2[0] + buffer[WordOrders2[ii + 01]];
                d = d << Shifts2[ii + 01] | d >> (32 - Shifts2[ii + 01]);

                c += (d & b) | (a & ~b);
                c += Constants2[0] + buffer[WordOrders2[ii + 02]];
                c = c << Shifts2[ii + 02] | c >> (32 - Shifts2[ii + 02]);

                b += (c & a) | (d & ~a);
                b += Constants2[0] + buffer[WordOrders2[ii + 03]];
                b = b << Shifts2[ii + 03] | b >> (32 - Shifts2[ii + 03]);
            }

            // Round 2
            for (int ii = 16; ii < 32; ii += 4)
            {
                a += (b | ~c) ^ d;
                a += Constants2[1] + buffer[WordOrders2[ii + 00]];
                a = a << Shifts2[ii + 00] | a >> (32 - Shifts2[ii + 00]);

                d += (a | ~b) ^ c;
                d += Constants2[1] + buffer[WordOrders2[ii + 01]];
                d = d << Shifts2[ii + 01] | d >> (32 - Shifts2[ii + 01]);

                c += (d | ~a) ^ b;
                c += Constants2[1] + buffer[WordOrders2[ii + 02]];
                c = c << Shifts2[ii + 02] | c >> (32 - Shifts2[ii + 02]);

                b += (c | ~d) ^ a;
                b += Constants2[1] + buffer[WordOrders2[ii + 03]];
                b = b << Shifts2[ii + 03] | b >> (32 - Shifts2[ii + 03]);
            }

            // Round 3
            for (int ii = 32; ii < 48; ii += 4)
            {
                a += (b & c) | (~b & d);
                a += Constants2[2] + buffer[WordOrders2[ii + 00]];
                a = a << Shifts2[ii + 00] | a >> (32 - Shifts2[ii + 00]);

                d += (a & b) | (~a & c);
                d += Constants2[2] + buffer[WordOrders2[ii + 01]];
                d = d << Shifts2[ii + 01] | d >> (32 - Shifts2[ii + 01]);

                c += (d & a) | (~d & b);
                c += Constants2[2] + buffer[WordOrders2[ii + 02]];
                c = c << Shifts2[ii + 02] | c >> (32 - Shifts2[ii + 02]);

                b += (c & d) | (~c & a);
                b += Constants2[2] + buffer[WordOrders2[ii + 03]];
                b = b << Shifts2[ii + 03] | b >> (32 - Shifts2[ii + 03]);
            }

            // Round 4
            for (int ii = 48; ii < 64; ii += 4)
            {
                a += (b ^ c ^ d);
                a += Constants2[3] + buffer[WordOrders2[ii + 00]];
                a = a << Shifts2[ii + 00] | a >> (32 - Shifts2[ii + 00]);

                d += (a ^ b ^ c);
                d += Constants2[3] + buffer[WordOrders2[ii + 01]];
                d = d << Shifts2[ii + 01] | d >> (32 - Shifts2[ii + 01]);

                c += (d ^ a ^ b);
                c += Constants2[3] + buffer[WordOrders2[ii + 02]];
                c = c << Shifts2[ii + 02] | c >> (32 - Shifts2[ii + 02]);

                b += (c ^ d ^ a);
                b += Constants2[3] + buffer[WordOrders2[ii + 03]];
                b = b << Shifts2[ii + 03] | b >> (32 - Shifts2[ii + 03]);
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
