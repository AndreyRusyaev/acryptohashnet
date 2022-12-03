using System;
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
        public int BlockSize { get { return BlockSizeValue; } }

        /// <summary>
        /// Initialization algorithm variables.
        /// </summary>
        public override void Initialize()
        {
            lastBlock.AsSpan().Clear();
            lastBlockLength = 0;
        }

        /// <summary>
        /// Processing block of bytes (size is @BlockSize), @array length must be >= than @offset + @BlockSize
        /// </summary>
        /// <param name="array">array of bytes</param>
        /// <param name="offset">offset from begin of block in @array</param>
        protected abstract void ProcessBlock(byte[] array, int offset);

        /// <summary>
        /// Processing final block of bytes (size is @length), @array length must be >= than @offset + @length
        /// </summary>
        /// <param name="array">array of bytes</param>
        /// <param name="offset">offset from begin of block in @array</param>
        /// <param name="length">length of final block</param>
        protected abstract byte[] ProcessFinalBlock(byte[] array, int offset, int length);

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

            if (lastBlockLength > 0)
            {
                int lastBlockRemaining = BlockSizeValue - lastBlockLength;
                if (length >= lastBlockRemaining)
                {
                    array.AsSpan(offset, lastBlockRemaining).CopyTo(lastBlock.AsSpan(lastBlockLength));

                    ProcessBlock(lastBlock, 0);
                    offset += lastBlockRemaining;
                    length -= lastBlockRemaining;

                    lastBlockLength = 0;
                }
            }

            while (length >= BlockSizeValue)
            {
                ProcessBlock(array, offset);
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
            
            return ProcessFinalBlock(lastBlock, 0, lastBlockLength);
        }
    }
}
