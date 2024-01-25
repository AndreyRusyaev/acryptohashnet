using System;
using System.Numerics;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS PUB 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
    /// </summary>
    public sealed class Sha3_256 : BlockHashAlgorithm
    {
        private readonly ulong[] state = new ulong[25];
        public Sha3_256() : base(136)
        {
            HashSizeValue = 256;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.AsSpan().Fill(0);
        }
        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            for (int jj = 0; jj < BlockSize / 8; jj += 1)
            {
                state[jj] ^= LittleEndian.ToUInt64(block.Slice(jj * 8, 8));
            }

            KeccakPermutation.Run(state);
        }

        protected override byte[] ProcessFinalBlock()
        {
            return LittleEndian.ToByteArray(state.AsSpan(0, 4));
        }

        protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var padding = new byte[BlockSize];
            lastBlock.CopyTo(padding);

            padding[lastBlock.Length] = 0x06; // 0000 0110
            padding[BlockSize - 1] |= 0x80;   // 1000 0000

            return padding;
        }
    }
}
