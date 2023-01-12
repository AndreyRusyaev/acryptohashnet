using System;
using System.Numerics;

namespace acryptohashnet
{
    /// <summary>
    /// RFC1319: The MD2 Message-Digest Algorithm
    /// https://datatracker.ietf.org/doc/html/rfc1319
    /// </summary>
    public sealed class MD2 : BlockHashAlgorithm
    {
        private static readonly int[] Pi = new int[]
        {
            041, 046, 067, 201,
            162, 216, 124, 001,
            061, 054, 084, 161,
            236, 240, 006, 019,

            098, 167, 005, 243,
            192, 199, 115, 140,
            152, 147, 043, 217,
            188, 076, 130, 202,

            030, 155, 087, 060,
            253, 212, 224, 022,
            103, 066, 111, 024,
            138, 023, 229, 018,

            190, 078, 196, 214,
            218, 158, 222, 073,
            160, 251, 245, 142,
            187, 047, 238, 122,

            169, 104, 121, 145,
            021, 178, 007, 063,
            148, 194, 016, 137,
            011, 034, 095, 033,

            128, 127, 093, 154,
            090, 144, 050, 039,
            053, 062, 204, 231,
            191, 247, 151, 003,

            255, 025, 048, 179,
            072, 165, 181, 209,
            215, 094, 146, 042,
            172, 086, 170, 198,

            079, 184, 056, 210,
            150, 164, 125, 182,
            118, 252, 107, 226,
            156, 116, 004, 241,

            069, 157, 112, 089,
            100, 113, 135, 032,
            134, 091, 207, 101,
            230, 045, 168, 002,

            027, 096, 037, 173,
            174, 176, 185, 246,
            028, 070, 097, 105,
            052, 064, 126, 015,

            085, 071, 163, 035,
            221, 081, 175, 058,
            195, 092, 249, 206,
            186, 197, 234, 038,

            044, 083, 013, 110,
            133, 040, 132, 009,
            211, 223, 205, 244,
            065, 129, 077, 082,

            106, 220, 055, 200,
            108, 193, 171, 250,
            036, 225, 123, 008,
            012, 189, 177, 074,

            120, 136, 149, 139,
            227, 099, 232, 109,
            233, 203, 213, 254,
            059, 000, 029, 057,

            242, 239, 183, 014,
            102, 088, 208, 228,
            166, 119, 114, 248,
            235, 117, 075, 010,

            049, 068, 080, 180,
            143, 237, 031, 026,
            219, 153, 141, 051,
            159, 017, 131, 020
        };

        private readonly HashState state = new HashState();

        public readonly int[] checkSum = new int[16];

        private readonly int[] buffer = new int[48];

        public MD2() : base(16)
        {
            HashSizeValue = 128;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.Initialize();
            checkSum.AsSpan().Clear();
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            ProcessBlockInternal(block);
            UpdateCheckSum(block);
        }

        protected override byte[] ProcessFinalBlock()
        {
            var finalBlock = new byte[BlockSizeValue];
            for (int ii = 0; ii < checkSum.Length; ii++)
            {
                finalBlock[ii] = unchecked((byte)(checkSum[ii] & 0xff));
            }

            ProcessBlockInternal(finalBlock);

            return state.ToByteArray();
        }

        protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var padding = new byte[BlockSizeValue];

            lastBlock.CopyTo(padding);

            byte paddingByte = (byte)(16 - (messageLength & 0xf));
            for (int ii = lastBlock.Length; ii < BlockSize; ii++)
            {
                padding[ii] = paddingByte;
            }

            return padding;
        }

        private void ProcessBlockInternal(ReadOnlySpan<byte> block)
        {
            // fill buffer
            for (int ii = 0; ii < 16; ii++)
            {
                buffer[ii] = state.state[ii];
            }

            // Expand buffer
            for (int ii = 16, jj = 0; ii < 32; ii++, jj++)
            {
                buffer[ii] = block[jj];
            }

            for (int ii = 32, jj = 0; ii < buffer.Length; ii++, jj++)
            {
                buffer[ii] = buffer[jj] ^ block[jj];
            }

            // do 18 rounds

            for (int ii = 0, piIndex = 0; ii < 18; ii++)
            {
                for (int jj = 0; jj < buffer.Length; jj++)
                {
                    piIndex = buffer[jj] ^= Pi[piIndex];
                }

                piIndex = (piIndex + ii) & 0xff; // % 256
            }

            // Copy to state
            for (int ii = 0; ii < state.state.Length; ii++)
            {
                state.state[ii] = (byte)(buffer[ii] & 0xff);
            }
        }

        private void UpdateCheckSum(ReadOnlySpan<byte> block)
        {
            for (int ii = 0, piIndex = checkSum[15]; ii < checkSum.Length; ii++)
            {
                piIndex = block[ii] ^ piIndex;
                piIndex = checkSum[ii] ^= Pi[piIndex];
            }
        }

        private sealed class HashState
        {
            public readonly byte[] state = new byte[16];

            public HashState()
            {
            }

            public void Initialize() 
            {
                state.AsSpan().Clear();
            }

            public byte[] ToByteArray()
            {
                byte[] result = new byte[16];

                Buffer.BlockCopy(state, 0, result, 0, result.Length);

                return state;
            }
        }
    }
}
