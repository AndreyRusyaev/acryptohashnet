using System;
using System.Numerics;

namespace acryptohashnet
{
    /// <summary>
    /// Tiger: A Fast New Cryptographic Hash Function (Designed in 1995)
    /// by Eli Biham & Ross Anderson
    /// https://www.cs.technion.ac.il/~biham/Reports/Tiger/
    /// </summary>
    public sealed class Tiger : TigerBase
    {
        public Tiger() : base()
        {
        }

        protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var paddingBlocks = lastBlock.Length + 8 > BlockSizeValue ? 2 : 1;
            var padding = new byte[paddingBlocks * BlockSizeValue];

            lastBlock.CopyTo(padding);

            // padding message with 00000001_00..000 bits
            padding[lastBlock.Length] = 0x01;

            int endOffset = padding.Length - 8;

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
    }
}
