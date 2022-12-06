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
            HashSizeValue = blockSize << 3;

            lastBlock = new byte[BlockSizeValue];
            lastBlockLength = 0;
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
        /// Processing block of bytes (size is @BlockSize), @array length must be >= than @offset + @BlockSize
        /// </summary>
        /// <param name="block">block of bytes</param>
        protected abstract void ProcessBlock(ReadOnlySpan<byte> block);

        /// <summary>
        /// Generate padding blocks for hash algorithm
        /// </summary>
        /// <param name="lastBlock"></param>
        /// <returns></returns>
        protected abstract byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength);

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
    }
}
