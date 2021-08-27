using System;

namespace Home.Andir.Cryptography
{
    public sealed class SHA256 : BlockHashAlgorithm
    {
        public SHA256() : base(64)
        {
            HashSizeValue = 256;
            
            this.finalBlock = new byte[BlockSize];
            this.Initialize();
        }

        private readonly IntCounter counter = new IntCounter(2);
        private readonly uint[] state = new uint[8];
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
            state[0] = 0x6a09e667;
            state[1] = 0xbb67ae85;
            state[2] = 0x3c6ef372;
            state[3] = 0xa54ff53a;
            state[4] = 0x510e527f;
            state[5] = 0x9b05688c;
            state[6] = 0x1f83d9ab;
            state[7] = 0x5be0cd19;
        }

        private static readonly uint[] constants = new uint[64]
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

        private uint[] buffer = new uint[64];

        protected override void ProcessBlock(byte[] array, int offset)
        {
            if (array.Length < offset + BlockSize)
                throw new ArgumentOutOfRangeException("offset");

            counter.Add(BlockSize << 3);

            // Fill buffer for transformations
            BigEndianBuffer.BlockCopy(array, offset, buffer, 0, BlockSize);

            for (int ii = 16; ii < 64; ii++)
                buffer[ii] = Ro1(buffer[ii - 2]) + buffer[ii - 7] + Ro0(buffer[ii - 15]) + buffer[ii - 16];

            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];
            uint f = state[5];
            uint g = state[6];
            uint h = state[7];

            for (int ii = 0; ii < buffer.Length; ii += 8)
            {
                // step 1
                h += constants[ii + 0] + buffer[ii + 0];
                h += (e & f) ^ (~e & g);
                h += Sig1(e);

                d += h;

                h += (a & b) ^ (a & c) ^ (b & c);
                h += Sig0(a);

                // step 2
                g += constants[ii + 1] + buffer[ii + 1];
                g += (d & e) ^ (~d & f);
                g += Sig1(d);

                c += g;

                g += (h & a) ^ (h & b) ^ (a & b);
                g += Sig0(h);

                // step 3
                f += constants[ii + 2] + buffer[ii + 2];
                f += (c & d) ^ (~c & e);
                f += Sig1(c);

                b += f;

                f += (g & h) ^ (g & a) ^ (h & a);
                f += Sig0(g);

                // step 4
                e += constants[ii + 3] + buffer[ii + 3];
                e += (b & c) ^ (~b & d);
                e += Sig1(b);

                a += e;

                e += (f & g) ^ (f & h) ^ (g & h);
                e += Sig0(f);

                // step 5
                d += constants[ii + 4] + buffer[ii + 4];
                d += (a & b) ^ (~a & c);
                d += Sig1(a);

                h += d;

                d += (e & f) ^ (e & g) ^ (f & g);
                d += Sig0(e);

                // step 6
                c += constants[ii + 5] + buffer[ii + 5];
                c += (h & a) ^ (~h & b);
                c += Sig1(h);

                g += c;

                c += (d & e) ^ (d & f) ^ (e & f);
                c += Sig0(d);

                // step 7
                b += constants[ii + 6] + buffer[ii + 6];
                b += (g & h) ^ (~g & a);
                b += Sig1(g);

                f += b;

                b += (c & d) ^ (c & e) ^ (d & e);
                b += Sig0(c);

                // step 8
                a += constants[ii + 7] + buffer[ii + 7];
                a += (f & g) ^ (~f & h);
                a += Sig1(f);

                e += a;

                a += (b & c) ^ (b & d) ^ (c & d);
                a += Sig0(b);
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
            if (length >= BlockSize
                || length > array.Length - offset)
                throw new ArgumentOutOfRangeException("length");

            counter.Add(length << 3); // arg * 8

            byte[] messageLength = counter.GetBytes();

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
                finalBlock[endOffset + ii] = messageLength[7 - ii];

            // Processing of last block
            ProcessBlock(finalBlock, 0);
        }

        protected override byte[] Result
        {
            get
            {
                // pack the results
                byte[] result = new byte[32];

                BigEndianBuffer.BlockCopy(state, 0, result, 0, result.Length);

                return result;
            }
        }

        private uint Ro0(uint x)
        {
            return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
        }

        private uint Ro1(uint x)
        {
            return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
        }

        private uint Sig0(uint x)
        {
            return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
        }

        private uint Sig1(uint x)
        {
            return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
        }
    }
}
