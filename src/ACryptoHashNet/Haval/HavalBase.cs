using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// HAVAL — A One-Way Hashing Algorithm with Variable Length of Output
    /// Designed by Yuliang Zheng, Josef Pieprzyk and Jennifer Seberry.
    /// </summary>
    public abstract class HavalBase : BlockHashAlgorithm
    {
        private const uint HavalVersion = 1;

        private static readonly uint[] WordOrders = new uint[]
        {
            // pass 2
            05, 14, 26, 18, 11, 28, 07, 16, 00, 23, 20, 22, 01, 10, 04, 08,
            30, 03, 21, 09, 17, 24, 29, 06, 19, 12, 15, 13, 02, 25, 31, 27,
            // pass 3
            19, 09, 04, 20, 28, 17, 08, 22, 29, 14, 25, 12, 24, 30, 16, 26,
            31, 15, 07, 03, 01, 00, 18, 27, 13, 06, 21, 10, 23, 11, 05, 02,
            // pass 4
            24, 04, 00, 14, 02, 07, 28, 23, 26, 06, 30, 20, 18, 25, 19, 03,
            22, 11, 31, 21, 08, 27, 12, 09, 01, 29, 05, 15, 17, 10, 16, 13,
            // pass 5
            27, 03, 21, 26, 17, 11, 20, 29, 19, 00, 12, 07, 13, 08, 31, 10,
            05, 09, 14, 30, 18, 06, 28, 24, 02, 23, 16, 22, 04, 01, 25, 15
        };

        private static readonly uint[] Constants = new uint[]
        {
            // pass 2
            0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c, 0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
            0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac, 0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
            0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7, 0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
            0xa458fea3, 0xf4933d7e, 0x0d95748f, 0x728eb658, 0x718bcd58, 0x82154aee, 0x7b54a41d, 0xc25a59b5,
            // pass 3
            0x9c30d539, 0x2af26013, 0xc5d1b023, 0x286085f0, 0xca417918, 0xb8db38ef, 0x8e79dcb0, 0x603a180e,
            0x6c9e0e8b, 0xb01e8a3e, 0xd71577c1, 0xbd314b27, 0x78af2fda, 0x55605c60, 0xe65525f3, 0xaa55ab94,
            0x57489862, 0x63e81440, 0x55ca396a, 0x2aab10b6, 0xb4cc5c34, 0x1141e8ce, 0xa15486af, 0x7c72e993,
            0xb3ee1411, 0x636fbc2a, 0x2ba9c55d, 0x741831f6, 0xce5c3e16, 0x9b87931e, 0xafd6ba33, 0x6c24cf5c,
            // pass 4
            0x7a325381, 0x28958677, 0x3b8f4898, 0x6b4bb9af, 0xc4bfe81b, 0x66282193, 0x61d809cc, 0xfb21a991,
            0x487cac60, 0x5dec8032, 0xef845d5d, 0xe98575b1, 0xdc262302, 0xeb651b88, 0x23893e81, 0xd396acc5,
            0x0f6d6ff3, 0x83f44239, 0x2e0b4482, 0xa4842004, 0x69c8f04a, 0x9e1f9b5e, 0x21c66842, 0xf6e96c9a,
            0x670c9c61, 0xabd388f0, 0x6a51a0d2, 0xd8542f68, 0x960fa728, 0xab5133a3, 0x6eef0b6c, 0x137a3be4,
            // pass 5
            0xba3bf050, 0x7efb2a98, 0xa1f1651d, 0x39af0176, 0x66ca593e, 0x82430e88, 0x8cee8619, 0x456f9fb4,
            0x7d84a5c3, 0x3b8b5ebe, 0xe06f75d8, 0x85c12073, 0x401a449f, 0x56c16aa6, 0x4ed3aa62, 0x363f7706,
            0x1bfedf72, 0x429b023d, 0x37d0d724, 0xd00a1248, 0xdb0fead3, 0x49f1c09b, 0x075372c9, 0x80991b7b,
            0x25d479d8, 0xf6e8def7, 0xe3fe501a, 0xb6794c3b, 0x976ce0bd, 0x04c006ba, 0xc1a94fb6, 0x409f60c4
        };

        private readonly HavalHashSize havalHashSize;

        private readonly HavalPassCount havalPassCount;

        private readonly byte[] signature = new byte[2];

        private readonly HashState state = new HashState();

        private readonly uint[] buffer = new uint[160];

        public HavalBase(HavalHashSize havalHashSize, HavalPassCount havalPassCount)
            : base(128)
        {
            this.havalHashSize = havalHashSize;
            this.havalPassCount = havalPassCount;

            uint hashSize = (uint)havalHashSize;
            uint passCount = (uint)havalPassCount;

            HashSizeValue = (int)havalHashSize;

            signature[0] = (byte)(
                      ((hashSize & 0x3) << 6)
                    | ((passCount & 0x7) << 3)
                    | (HavalVersion & 0x7));
            signature[1] = (byte)((hashSize >> 2) & 0xff);
        }

        public override void Initialize()
        {
            base.Initialize();
            state.Initialize();
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            LittleEndian.Copy(block, buffer.AsSpan(0, BlockSizeValue));

            for (int ii = 32; ii < buffer.Length; ii++)
            {
                buffer[ii] = buffer[WordOrders[ii - 32]];
            }

            switch (havalPassCount)
            {
                case HavalPassCount.Pass3:
                    ProcessBlock3Pass();
                    break;
                case HavalPassCount.Pass4:
                    ProcessBlock4Pass();
                    break;
                case HavalPassCount.Pass5:
                    ProcessBlock5Pass();
                    break;
            }
        }

        protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var paddingBlocks = lastBlock.Length + 10 > BlockSizeValue ? 2 : 1;
            var padding = new byte[paddingBlocks * BlockSizeValue];

            lastBlock.CopyTo(padding);

            // padding message with 100..000 bits
            padding[lastBlock.Length] = 0x01;

            int endOffset = padding.Length - 10;

            padding[endOffset + 0] = signature[0];
            padding[endOffset + 1] = signature[1];

            endOffset += 2;

            byte[] messageLengthInBits = (messageLength << 3).ToByteArray();
            if (messageLengthInBits.Length > 8)
            {
                var supportedLength = BigInteger.Pow(2, 8 << 3) - 1;
                throw new InvalidOperationException(
                    $"Message is too long for this hash algorithm. Actual: {messageLength}, Max supported: {supportedLength} bytes.");
            }

            for (int ii = 0; ii < messageLengthInBits.Length; ii++)
            {
                padding[endOffset + ii] = messageLengthInBits[ii];
            }

            return padding;
        }

        protected override byte[] ProcessFinalBlock()
        {
            return state.ToByteArray(havalHashSize);
        }

        private void ProcessBlock3Pass()
        {
            uint t0 = state.T0;
            uint t1 = state.T1;
            uint t2 = state.T2;
            uint t3 = state.T3;
            uint t4 = state.T4;
            uint t5 = state.T5;
            uint t6 = state.T6;
            uint t7 = state.T7;

            // pass 1
            for (int ii = 0; ii < 32; ii += 8)
            {
                uint t = F1phi3(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0];

                t = F1phi3(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1];

                t = F1phi3(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2];

                t = F1phi3(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3];

                t = F1phi3(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4];

                t = F1phi3(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5];

                t = F1phi3(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6];

                t = F1phi3(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7];
            }

            // pass 2
            for (int ii = 32; ii < 64; ii += 8)
            {
                uint t = F2phi3(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F2phi3(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F2phi3(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F2phi3(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F2phi3(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F2phi3(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F2phi3(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F2phi3(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            // pass 3
            for (int ii = 64; ii < 96; ii += 8)
            {
                uint t = F3phi3(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F3phi3(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F3phi3(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F3phi3(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F3phi3(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F3phi3(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F3phi3(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F3phi3(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            state.T0 += t0;
            state.T1 += t1;
            state.T2 += t2;
            state.T3 += t3;
            state.T4 += t4;
            state.T5 += t5;
            state.T6 += t6;
            state.T7 += t7;
        }

        private void ProcessBlock4Pass()
        {
            uint t0 = state.T0;
            uint t1 = state.T1;
            uint t2 = state.T2;
            uint t3 = state.T3;
            uint t4 = state.T4;
            uint t5 = state.T5;
            uint t6 = state.T6;
            uint t7 = state.T7;

            // pass 1
            for (int ii = 0; ii < 32; ii += 8)
            {
                uint t = F1phi4(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0];

                t = F1phi4(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1];

                t = F1phi4(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2];

                t = F1phi4(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3];

                t = F1phi4(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4];

                t = F1phi4(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5];

                t = F1phi4(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6];

                t = F1phi4(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7];
            }

            // pass 2
            for (int ii = 32; ii < 64; ii += 8)
            {
                uint t = F2phi4(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F2phi4(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F2phi4(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F2phi4(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F2phi4(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F2phi4(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F2phi4(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F2phi4(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            // pass 3
            for (int ii = 64; ii < 96; ii += 8)
            {
                uint t = F3phi4(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F3phi4(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F3phi4(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F3phi4(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F3phi4(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F3phi4(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F3phi4(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F3phi4(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            // pass 4
            for (int ii = 96; ii < 128; ii += 8)
            {
                uint t = F4phi4(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F4phi4(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F4phi4(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F4phi4(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F4phi4(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F4phi4(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F4phi4(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F4phi4(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            state.T0 += t0;
            state.T1 += t1;
            state.T2 += t2;
            state.T3 += t3;
            state.T4 += t4;
            state.T5 += t5;
            state.T6 += t6;
            state.T7 += t7;
        }

        private void ProcessBlock5Pass()
        {
            uint t0 = state.T0;
            uint t1 = state.T1;
            uint t2 = state.T2;
            uint t3 = state.T3;
            uint t4 = state.T4;
            uint t5 = state.T5;
            uint t6 = state.T6;
            uint t7 = state.T7;

            // pass 1
            for (int ii = 0; ii < 32; ii += 8)
            {
                uint t = F1phi5(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0];

                t = F1phi5(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1];

                t = F1phi5(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2];

                t = F1phi5(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3];

                t = F1phi5(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4];

                t = F1phi5(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5];

                t = F1phi5(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6];

                t = F1phi5(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7];
            }

            // pass 2
            for (int ii = 32; ii < 64; ii += 8)
            {
                uint t = F2phi5(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F2phi5(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F2phi5(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F2phi5(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7);
                t4 += buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F2phi5(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F2phi5(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F2phi5(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F2phi5(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            // pass 3
            for (int ii = 64; ii < 96; ii += 8)
            {
                uint t = F3phi5(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F3phi5(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F3phi5(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F3phi5(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F3phi5(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F3phi5(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F3phi5(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F3phi5(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            // pass 4
            for (int ii = 96; ii < 128; ii += 8)
            {
                uint t = F4phi5(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F4phi5(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F4phi5(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F4phi5(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F4phi5(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F4phi5(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F4phi5(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F4phi5(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            // pass 5
            for (int ii = 128; ii < 160; ii += 8)
            {
                uint t = F5phi5(t6, t5, t4, t3, t2, t1, t0);

                t7 = t7.RotateRight(11);
                t7 += t.RotateRight(7) + buffer[ii + 0] + Constants[(ii + 0) - 32];

                t = F5phi5(t5, t4, t3, t2, t1, t0, t7);

                t6 = t6.RotateRight(11);
                t6 += t.RotateRight(7) + buffer[ii + 1] + Constants[(ii + 1) - 32];

                t = F5phi5(t4, t3, t2, t1, t0, t7, t6);

                t5 = t5.RotateRight(11);
                t5 += t.RotateRight(7) + buffer[ii + 2] + Constants[(ii + 2) - 32];

                t = F5phi5(t3, t2, t1, t0, t7, t6, t5);

                t4 = t4.RotateRight(11);
                t4 += t.RotateRight(7) + buffer[ii + 3] + Constants[(ii + 3) - 32];

                t = F5phi5(t2, t1, t0, t7, t6, t5, t4);

                t3 = t3.RotateRight(11);
                t3 += t.RotateRight(7) + buffer[ii + 4] + Constants[(ii + 4) - 32];

                t = F5phi5(t1, t0, t7, t6, t5, t4, t3);

                t2 = t2.RotateRight(11);
                t2 += t.RotateRight(7) + buffer[ii + 5] + Constants[(ii + 5) - 32];

                t = F5phi5(t0, t7, t6, t5, t4, t3, t2);

                t1 = t1.RotateRight(11);
                t1 += t.RotateRight(7) + buffer[ii + 6] + Constants[(ii + 6) - 32];

                t = F5phi5(t7, t6, t5, t4, t3, t2, t1);

                t0 = t0.RotateRight(11);
                t0 += t.RotateRight(7) + buffer[ii + 7] + Constants[(ii + 7) - 32];
            }

            state.T0 += t0;
            state.T1 += t1;
            state.T2 += t2;
            state.T3 += t3;
            state.T4 += t4;
            state.T5 += t5;
            state.T6 += t6;
            state.T7 += t7;
        }

        // common

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F1(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return x1 & (x0 ^ x4) ^ x2 & x5 ^ x3 & x6 ^ x0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F2(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return x2 & (x1 & ~x3 ^ x4 & x5 ^ x6 ^ x0) ^ x4 & (x1 ^ x5) ^ x3 & x5 ^ x0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F3(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return x3 & (x1 & x2 ^ x6 ^ x0) ^ x1 & x4 ^ x2 & x5 ^ x0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F4(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return x4 & (x5 & ~x2 ^ x3 & ~x6 ^ x1 ^ x6 ^ x0) ^ x3 & (x1 & x2 ^ x5 ^ x6) ^ x2 & x6 ^ x0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return x0 & (x1 & x2 & x3 ^ ~x5) ^ x1 & x4 ^ x2 & x5 ^ x3 & x6;
        }

        // pass 3
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F1phi3(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F1(x1, x0, x3, x5, x6, x2, x4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F2phi3(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F2(x4, x2, x1, x0, x5, x3, x6);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F3phi3(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F3(x6, x1, x2, x3, x4, x5, x0);
        }

        // pass 4
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F1phi4(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F1(x2, x6, x1, x4, x5, x3, x0);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F2phi4(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F2(x3, x5, x2, x0, x1, x6, x4);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F3phi4(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F3(x1, x4, x3, x6, x0, x2, x5);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F4phi4(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F4(x6, x4, x0, x5, x2, x1, x3);
        }

        // pass 5
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F1phi5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F1(x3, x4, x1, x0, x5, x2, x6);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F2phi5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F2(x6, x2, x1, x0, x3, x4, x5);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F3phi5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F3(x2, x6, x0, x4, x3, x1, x5);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F4phi5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F4(x1, x5, x3, x2, x0, x4, x6);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint F5phi5(uint x6, uint x5, uint x4, uint x3, uint x2, uint x1, uint x0)
        {
            return F5(x2, x5, x0, x6, x4, x3, x1);
        }

        private sealed class HashState
        {
            public uint T0;
            public uint T1;
            public uint T2;
            public uint T3;
            public uint T4;
            public uint T5;
            public uint T6;
            public uint T7;

            public HashState()
            {
                Initialize();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Initialize()
            {
                T0 = 0x243f6a88;
                T1 = 0x85a308d3;
                T2 = 0x13198a2e;
                T3 = 0x03707344;
                T4 = 0xa4093822;
                T5 = 0x299f31d0;
                T6 = 0x082efa98;
                T7 = 0xec4e6c89;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public byte[] ToByteArray(HavalHashSize havalHashSize)
            {
                switch (havalHashSize)
                {
                    case HavalHashSize.HashSize128:
                        return TailorResult128();
                    case HavalHashSize.HashSize160:
                        return TailorResult160();
                    case HavalHashSize.HashSize192:
                        return TailorResult192();
                    case HavalHashSize.HashSize224:
                        return TailorResult224();
                    case HavalHashSize.HashSize256:
                        break;
                    default:
                        throw new ArgumentOutOfRangeException(nameof(havalHashSize));
                }

                byte[] result = new byte[32];
                LittleEndian.Copy(T0, result.AsSpan(0, 4));
                LittleEndian.Copy(T1, result.AsSpan(4, 4));
                LittleEndian.Copy(T2, result.AsSpan(8, 4));
                LittleEndian.Copy(T3, result.AsSpan(12, 4));
                LittleEndian.Copy(T4, result.AsSpan(16, 4));
                LittleEndian.Copy(T5, result.AsSpan(20, 4));
                LittleEndian.Copy(T6, result.AsSpan(24, 4));
                LittleEndian.Copy(T7, result.AsSpan(28, 4));

                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private byte[] TailorResult128()
            {
                uint temp;

                temp = (T7 & 0x000000ff) | (T6 & 0xff000000) | (T5 & 0x00ff0000) | (T4 & 0x0000ff00);
                T0 += temp.RotateRight(8);

                temp = (T7 & 0x0000ff00) | (T6 & 0x000000ff) | (T5 & 0xff000000) | (T4 & 0x00ff0000);
                T1 += temp.RotateRight(16);

                temp = (T7 & 0x00ff0000) | (T6 & 0x0000ff00) | (T5 & 0x000000ff) | (T4 & 0xff000000);
                T2 += temp.RotateRight(24);

                temp = (T7 & 0xff000000) | (T6 & 0x00ff0000) | (T5 & 0x0000ff00) | (T4 & 0x000000ff);
                T3 += temp;

                byte[] result = new byte[16];
                LittleEndian.Copy(T0, result.AsSpan(0, 4));
                LittleEndian.Copy(T1, result.AsSpan(4, 4));
                LittleEndian.Copy(T2, result.AsSpan(8, 4));
                LittleEndian.Copy(T3, result.AsSpan(12, 4));
                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private byte[] TailorResult160()
            {
                uint temp;

                temp = (T7 & (0x0000003fU << 00)) | (T6 & (0x0000007fU << 25)) | (T5 & (0x0000003fU << 19));
                T0 += temp.RotateRight(19);

                temp = (T7 & (0x0000003fU << 06)) | (T6 & (0x0000003fU << 00)) | (T5 & (0x0000007fU << 25));
                T1 += temp.RotateRight(25);

                temp = (T7 & (0x0000007fU << 12)) | (T6 & (0x0000003fU << 06)) | (T5 & (0x0000003fU << 00));
                T2 += temp;

                temp = (T7 & (0x0000003fU << 19)) | (T6 & (0x0000007fU << 12)) | (T5 & (0x0000003fU << 06));
                T3 += temp >> 6;

                temp = (T7 & (0x0000007fU << 25)) | (T6 & (0x0000003fU << 19)) | (T5 & (0x0000007fU << 12));
                T4 += temp >> 12;

                byte[] result = new byte[20];
                LittleEndian.Copy(T0, result.AsSpan(0, 4));
                LittleEndian.Copy(T1, result.AsSpan(4, 4));
                LittleEndian.Copy(T2, result.AsSpan(8, 4));
                LittleEndian.Copy(T3, result.AsSpan(12, 4));
                LittleEndian.Copy(T4, result.AsSpan(16, 4));
                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private byte[] TailorResult192()
            {
                uint temp;

                temp = (T7 & (0x0000001fU << 00)) | (T6 & (0x0000003fU << 26));
                T0 += temp.RotateRight(26);

                temp = (T7 & (0x0000001fU << 05)) | (T6 & (0x0000001fU << 00));
                T1 += temp;

                temp = (T7 & (0x0000003fU << 10)) | (T6 & (0x0000001fU << 05));
                T2 += temp >> 5;

                temp = (T7 & (0x0000001fU << 16)) | (T6 & (0x0000003fU << 10));
                T3 += temp >> 10;

                temp = (T7 & (0x0000001fU << 21)) | (T6 & (0x0000001fU << 16));
                T4 += temp >> 16;

                temp = (T7 & (0x0000003fU << 26)) | (T6 & (0x0000001fU << 21));
                T5 += temp >> 21;

                byte[] result = new byte[24];
                LittleEndian.Copy(T0, result.AsSpan(0, 4));
                LittleEndian.Copy(T1, result.AsSpan(4, 4));
                LittleEndian.Copy(T2, result.AsSpan(8, 4));
                LittleEndian.Copy(T3, result.AsSpan(12, 4));
                LittleEndian.Copy(T4, result.AsSpan(16, 4));
                LittleEndian.Copy(T5, result.AsSpan(20, 4));
                return result;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private byte[] TailorResult224()
            {
                T0 += (T7 >> 27) & 0x1f;
                T1 += (T7 >> 22) & 0x1f;
                T2 += (T7 >> 18) & 0x0f;
                T3 += (T7 >> 13) & 0x1f;
                T4 += (T7 >> 09) & 0x0f;
                T5 += (T7 >> 04) & 0x1f;
                T6 += (T7 >> 00) & 0x0f;

                byte[] result = new byte[28];
                LittleEndian.Copy(T0, result.AsSpan(0, 4));
                LittleEndian.Copy(T1, result.AsSpan(4, 4));
                LittleEndian.Copy(T2, result.AsSpan(8, 4));
                LittleEndian.Copy(T3, result.AsSpan(12, 4));
                LittleEndian.Copy(T4, result.AsSpan(16, 4));
                LittleEndian.Copy(T5, result.AsSpan(20, 4));
                LittleEndian.Copy(T6, result.AsSpan(24, 4));
                return result;
            }
        }
    }
}
