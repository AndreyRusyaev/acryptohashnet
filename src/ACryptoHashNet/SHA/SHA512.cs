using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// </summary>
    public sealed class SHA512 : BlockHashAlgorithm
    {
        private static readonly ulong[] Constants = new ulong[]
        {
            // round 1
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            // round 2
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            // round 3
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            // round 4
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            // round 5
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            // round 6
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            // round 7
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            // round 8
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            // round 9
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            // round 10
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        private readonly BigCounter processedLength = new BigCounter(16);

        private readonly ulong[] state = new ulong[8];

        private readonly ulong[] buffer = new ulong[80];

        private readonly byte[] finalBlock;

        public SHA512() : base(128)
        {
            HashSizeValue = 512;

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
            BigEndianBuffer.BlockCopy(array, offset, buffer, 0, BlockSize);

            for (int ii = 16; ii < buffer.Length; ii++)
            {
                buffer[ii] = Ro1(buffer[ii - 2]) + buffer[ii - 7] + Ro0(buffer[ii - 15]) + buffer[ii - 16];
            }

            ulong a = state[0];
            ulong b = state[1];
            ulong c = state[2];
            ulong d = state[3];
            ulong e = state[4];
            ulong f = state[5];
            ulong g = state[6];
            ulong h = state[7];

            for (int ii = 0; ii < buffer.Length - 7; ii += 8)
            {
                // step 1
                h += buffer[ii + 0] + Constants[ii + 0] + SHAFunctions.Ch(e, f, g) + Sig1(e);
                d += h;
                h += SHAFunctions.Maj(a, b, c) + Sig0(a);

                // step 2
                g += buffer[ii + 1] + Constants[ii + 1] + SHAFunctions.Ch(d, e, f) + Sig1(d);
                c += g;
                g += SHAFunctions.Maj(h, a, b) + Sig0(h);

                // step 3
                f += buffer[ii + 2] + Constants[ii + 2] + SHAFunctions.Ch(c, d, e) + Sig1(c);
                b += f;
                f += SHAFunctions.Maj(g, h, a) + Sig0(g);

                // step 4
                e += buffer[ii + 3] + Constants[ii + 3] + SHAFunctions.Ch(b, c, d) + Sig1(b);
                a += e;
                e += SHAFunctions.Maj(f, g, h) + Sig0(f);

                // step 5
                d += buffer[ii + 4] + Constants[ii + 4] + SHAFunctions.Ch(a, b, c) + Sig1(a);
                h += d;
                d += SHAFunctions.Maj(e, f, g) + Sig0(e);

                // step 6
                c += buffer[ii + 5] + Constants[ii + 5] + SHAFunctions.Ch(h, a, b) + Sig1(h);
                g += c;
                c += SHAFunctions.Maj(d, e, f) + Sig0(d);

                // step 7
                b += buffer[ii + 6] + Constants[ii + 6] + SHAFunctions.Ch(g, h, a) + Sig1(g);
                f += b;
                b += SHAFunctions.Maj(c, d, e) + Sig0(c);

                // step 8
                a += buffer[ii + 7] + Constants[ii + 7] + SHAFunctions.Ch(f, g, h) + Sig1(f);
                e += a;
                a += SHAFunctions.Maj(b, c, d) + Sig0(b);
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        protected override void ProcessFinalBlock(byte[] array, int offset, int length)
        {
            processedLength.Add(length << 3); // * 8

            byte[] messageLength = processedLength.GetBytes();

            Buffer.BlockCopy(array, offset, finalBlock, 0, length);

            // padding message with 100..000 bits
            finalBlock[length] = 0x80;

            int endOffset = BlockSize - 16;
            if (length >= endOffset)
            {
                ProcessBlock(finalBlock, 0);

                Array.Clear(finalBlock, 0, finalBlock.Length);
            }

            for (int ii = 0; ii < 16; ii++)
            {
                finalBlock[endOffset + ii] = messageLength[15 - ii];
            }

            // Processing of last block
            ProcessBlock(finalBlock, 0);
        }

        protected override byte[] Result
        {
            get
            {
                byte[] result = new byte[64];

                BigEndianBuffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Ro0(ulong x)
        {
            return Bits.RotateRight(x, 1) ^ Bits.RotateRight(x, 8) ^ (x >> 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Ro1(ulong x)
        {
            return Bits.RotateRight(x, 19) ^ Bits.RotateRight(x, 61) ^ (x >> 6);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Sig0(ulong x)
        {
            return Bits.RotateRight(x, 28) ^ Bits.RotateRight(x, 34) ^ Bits.RotateRight(x, 39);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Sig1(ulong x)
        {
            return Bits.RotateRight(x, 14) ^ Bits.RotateRight(x, 18) ^ Bits.RotateRight(x, 41);
        }

        private void InitializeState()
        {
            state[0] = 0x6a09e667f3bcc908;
            state[1] = 0xbb67ae8584caa73b;
            state[2] = 0x3c6ef372fe94f82b;
            state[3] = 0xa54ff53a5f1d36f1;
            state[4] = 0x510e527fade682d1;
            state[5] = 0x9b05688c2b3e6c1f;
            state[6] = 0x1f83d9abfb41bd6b;
            state[7] = 0x5be0cd19137e2179;
        }
    }
}
