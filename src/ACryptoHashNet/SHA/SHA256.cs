using System;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// </summary>
    public sealed class SHA256 : BlockHashAlgorithm
    {
        private static readonly uint[] Constants = new uint[64]
        {
            // round 1
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            // round 2
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            // round 3
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            // round 4
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            // round 5
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            // round 6
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            // round 7
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            // round 8
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private readonly BigCounter processedLength = new BigCounter(8);

        private readonly uint[] state = new uint[8];

        private readonly uint[] buffer = new uint[64];

        private readonly byte[] finalBlock;

        public SHA256() : base(64)
        {
            HashSizeValue = 256;
            
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
                buffer[ii] = SHAFunctions.Ro1(buffer[ii - 2]) + buffer[ii - 7] + SHAFunctions.Ro0(buffer[ii - 15]) + buffer[ii - 16];
            }

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];
            uint f = state[5];
            uint g = state[6];
            uint h = state[7];

            for (int ii = 0; ii < buffer.Length - 7; ii += 8)
            {
                // step 1
                h += buffer[ii + 0] + Constants[ii + 0] + SHAFunctions.Ch(e, f, g) + SHAFunctions.Sig1(e);
                d += h;
                h += SHAFunctions.Maj(a, b, c) + SHAFunctions.Sig0(a);

                // step 2
                g += buffer[ii + 1] + Constants[ii + 1] + SHAFunctions.Ch(d, e, f) + SHAFunctions.Sig1(d);
                c += g;
                g += SHAFunctions.Maj(h, a, b) + SHAFunctions.Sig0(h);

                // step 3
                f += buffer[ii + 2] + Constants[ii + 2] + SHAFunctions.Ch(c, d, e) + SHAFunctions.Sig1(c);
                b += f;
                f += SHAFunctions.Maj(g, h, a) + SHAFunctions.Sig0(g);

                // step 4
                e += buffer[ii + 3] + Constants[ii + 3] + SHAFunctions.Ch(b, c, d) + SHAFunctions.Sig1(b);
                a += e;
                e += SHAFunctions.Maj(f, g, h) + SHAFunctions.Sig0(f);

                // step 5
                d += buffer[ii + 4] + Constants[ii + 4] + SHAFunctions.Ch(a, b, c) + SHAFunctions.Sig1(a);
                h += d;
                d += SHAFunctions.Maj(e, f, g) + SHAFunctions.Sig0(e);

                // step 6
                c += buffer[ii + 5] + Constants[ii + 5] + SHAFunctions.Ch(h, a, b) + SHAFunctions.Sig1(h);
                g += c;
                c += SHAFunctions.Maj(d, e, f) + SHAFunctions.Sig0(d);

                // step 7
                b += buffer[ii + 6] + Constants[ii + 6] + SHAFunctions.Ch(g, h, a) + SHAFunctions.Sig1(g);
                f += b;
                b += SHAFunctions.Maj(c, d, e) + SHAFunctions.Sig0(c);

                // step 8
                a += buffer[ii + 7] + Constants[ii + 7] + SHAFunctions.Ch(f, g, h) + SHAFunctions.Sig1(f);
                e += a;
                a += SHAFunctions.Maj(b, c, d) + SHAFunctions.Sig0(b);
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
                byte[] result = new byte[32];

                BigEndianBuffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
            }
        }

        private void InitializeState()
        {
            state[0] = 0x6a09e667;
            state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372;
            state[3] = 0xa54ff53a;
            state[4] = 0x510e527f;
            state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab;
            state[7] = 0x5be0cd19;
        }
    }
}
