using System;
using System.Numerics;
using System.Security.Cryptography;

namespace acryptohashnet
{
    /// <summary>
    /// Represents the base class from which all implementation of block hash algorithms must derive.
    /// </summary>
    public abstract class BlockHashAlgorithm : HashAlgorithm
    {
        protected readonly int BlockSizeValue;

        protected PaddingType PaddingType = PaddingType.Custom;

        private readonly byte[] lastBlock;

        private int lastBlockLength;

        private BigInteger messageLength;

        /// <summary>
        /// Block hash algorithm ctor.
        /// </summary>
        /// <param name="blockSize">size of the block for algorithm in bytes</param>
        public BlockHashAlgorithm(int blockSize)
        {
            BlockSizeValue = blockSize;
            HashSizeValue = blockSize << 3; // * 8

            lastBlock = new byte[BlockSizeValue];
        }

        /// <summary>
        /// Size of algorithm block in bytes.
        /// </summary>
        public int BlockSize => BlockSizeValue;

        /// <summary>
        /// Initialization algorithm variables.
        /// </summary>
        public override void Initialize()
        {
            messageLength = 0;
            lastBlock.AsSpan().Clear();
            lastBlockLength = 0;
        }

        /// <summary>
        /// Processing block of bytes (size is @BlockSize).
        /// </summary>
        /// <param name="block">block of bytes</param>
        protected abstract void ProcessBlock(ReadOnlySpan<byte> block);

        /// <summary>
        /// Generate padding blocks for hash algorithm
        /// </summary>
        /// <param name="lastBlock">last unaligned block that should be padded</param>
        /// <param name="messageLength">message length in bytes</param>
        /// <returns></returns>
        protected virtual byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            switch (PaddingType)
            {
                case PaddingType.Custom:
                    throw new InvalidOperationException("Custom padding type should override GeneratePaddingBlocks method.");
                case PaddingType.OneZeroFillAnd8BytesMessageLengthLittleEndian:
                    return GenerateOneZeroFillAnd8BytesMessageLengthLittleEndianPadding(lastBlock, messageLength);
                case PaddingType.OneZeroFillAnd8BytesMessageLengthBigEndian:
                    return GenerateOneZeroFillAnd8BytesMessageLengthBigEndianPadding(lastBlock, messageLength);
                case PaddingType.OneZeroFillAnd16BytesMessageLengthBigEndian:
                    return GenerateOneZeroFillAnd16BytesMessageLengthBigEndianPadding(lastBlock, messageLength);
                default:
                    throw new InvalidOperationException($"Unsupported padding type '{PaddingType}'.");
            }
        }

        protected abstract byte[] ProcessFinalBlock();

        /// <summary>
        /// Main hash procedure.
        /// </summary>
        /// <param name="array">byte array</param>
        /// <param name="offset">offset in array</param>
        /// <param name="length">length of block for processing</param>
        protected sealed override void HashCore(byte[] array, int offset, int length)
        {
            if (length == 0)
            {
                return;
            }

            messageLength += length;

            if (lastBlockLength > 0)
            {
                int lastBlockRemaining = BlockSizeValue - lastBlockLength;
                if (length >= lastBlockRemaining)
                {
                    array.AsSpan(offset, lastBlockRemaining).CopyTo(lastBlock.AsSpan(lastBlockLength));

                    ProcessBlock(lastBlock);
                    offset += lastBlockRemaining;
                    length -= lastBlockRemaining;

                    lastBlockLength = 0;
                }
            }

            while (length >= BlockSizeValue)
            {
                ProcessBlock(array.AsSpan(offset, BlockSizeValue));
                offset += BlockSizeValue;
                length -= BlockSizeValue;
            }

            if (length > 0)
            {
                array.AsSpan(offset, length).CopyTo(lastBlock.AsSpan(lastBlockLength));
                lastBlockLength += length;
            }
        }

        /// <summary>
        /// Hash final block.
        /// </summary>
        /// <returns>hash value</returns>
        protected sealed override byte[] HashFinal()
        {
            if (lastBlockLength > lastBlock.Length)
            {
                throw new InvalidOperationException("lastBlockLength > lastBlock.Length");
            }

            var padding = GeneratePaddingBlocks(lastBlock.AsSpan(0, lastBlockLength), messageLength);
            for (int ii = 0; ii < padding.Length; ii += BlockSizeValue)
            {
                ProcessBlock(padding.AsSpan(ii, BlockSizeValue));
            }

            return ProcessFinalBlock();
        }

        private byte[] GenerateOneZeroFillAnd8BytesMessageLengthLittleEndianPadding(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var paddingBlocks = lastBlock.Length + 8 >= BlockSizeValue ? 2 : 1;
            var padding = new byte[paddingBlocks * BlockSizeValue];

            lastBlock.CopyTo(padding);

            padding[lastBlock.Length] = 0x80;

            byte[] messageLengthInBits = (messageLength << 3).ToByteArray();
            if (messageLengthInBits.Length > 8)
            {
                var supportedLength = BigInteger.Pow(2, 8 << 3) - 1;
                throw new InvalidOperationException(
                    $"Message is too long for this hash algorithm. Actual: {messageLength}, Max supported: {supportedLength} bytes.");
            }

            var endOffset = padding.Length - 8;
            for (int ii = 0; ii < messageLengthInBits.Length; ii++)
            {
                padding[endOffset + ii] = messageLengthInBits[ii];
            }

            return padding;
        }

        private byte[] GenerateOneZeroFillAnd8BytesMessageLengthBigEndianPadding(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var paddingBlocks = lastBlock.Length + 8 >= BlockSizeValue ? 2 : 1;
            var padding = new byte[paddingBlocks * BlockSizeValue];

            lastBlock.CopyTo(padding);

            padding[lastBlock.Length] = 0x80;

            byte[] messageLengthInBits = (messageLength << 3).ToByteArray();
            if (messageLengthInBits.Length > 8)
            {
                var supportedLength = BigInteger.Pow(2, 8 << 3) - 1;
                throw new InvalidOperationException(
                    $"Message is too long for this hash algorithm. Actual: {messageLength}, Max supported: {supportedLength} bytes.");
            }

            var endOffset = padding.Length - 8;
            for (int ii = 8 - messageLengthInBits.Length; ii < 8; ii++)
            {
                padding[endOffset + ii] = messageLengthInBits[7 - ii];
            }

            return padding;
        }

        private byte[] GenerateOneZeroFillAnd16BytesMessageLengthBigEndianPadding(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
        {
            var paddingBlocks = lastBlock.Length + 16 >= BlockSizeValue ? 2 : 1;
            var padding = new byte[paddingBlocks * BlockSizeValue];

            lastBlock.CopyTo(padding);

            padding[lastBlock.Length] = 0x80;

            byte[] messageLengthInBits = (messageLength << 3).ToByteArray();
            if (messageLengthInBits.Length > 16)
            {
                var supportedLength = BigInteger.Pow(2, 16 << 3) - 1;
                throw new InvalidOperationException(
                    $"Message is too long for this hash algorithm. Actual: {messageLength}, Max supported: {supportedLength} bytes.");
            }

            var endOffset = padding.Length - 16;
            for (int ii = 16 - messageLengthInBits.Length; ii < 16; ii++)
            {
                padding[endOffset + ii] = messageLengthInBits[15 - ii];
            }

            return padding;
        }
    }
}
