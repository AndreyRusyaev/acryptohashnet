using System;
using System.Numerics;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS PUB 202: SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions
    /// </summary>
    public sealed class Sha3_224 : BlockHashAlgorithm
    {
        private readonly ulong[] state = new ulong[25];

        public Sha3_224() : base(144)
        {
            HashSizeValue = 224;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.AsSpan().Fill(0);
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            for (int ii = 0; ii < BlockSize / 8; ii += 1)
            {
                state[ii] ^= LittleEndian.ToUInt64(block.Slice(ii * 8, 8));
            }

            Keccak.Permute(state);
        }

        protected override byte[] ProcessFinalBlock()
        {
            return LittleEndian.ToByteArray(state.AsSpan(0, 4)).AsSpan(0, 28).ToArray();
        }

        protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var padding = new byte[BlockSize];
            lastBlock.CopyTo(padding);

            padding[lastBlock.Length] = 0x06;    // 0000 0110
            padding[padding.Length - 1] |= 0x80; // 1000 0000

            return padding;
        }
    }
}
