using System;
using System.Security.Cryptography;

namespace Home.Andir.Cryptography
{
    /// <summary>
    /// Represents the base class from which all implementation of block hash algorithms must derive.
    /// </summary>
    public abstract class BlockHashAlgorithm : HashAlgorithm
    {
        private readonly byte[] lastBlock;
        private int lastBlockLength;

        /// <summary>
        /// Constructor.
        /// </summary>
        public BlockHashAlgorithm(int blockSize) : base()
        {
            this.BlockSize = blockSize;

            this.lastBlock = new byte[this.BlockSize];
            this.lastBlockLength = 0;
        }

        public int BlockSize { get; private set; }

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
        protected abstract void ProcessFinalBlock(byte[] array, int offset, int length);

        /// <summary>
        /// Resulting value of algorithm
        /// </summary>
        /// <value>byte array with hash value</value>
        protected abstract byte[] Result { get; }

        #region HashAlghorithm implementation

        /// <summary>
        /// Initialization algorithm variables.
        /// </summary>
        public override void Initialize()
        {
            Array.Clear(lastBlock, 0, lastBlock.Length);
            this.lastBlockLength = 0;
        }

        /// <summary>
        /// Main hash procedure.
        /// </summary>
        /// <param name="array">byte array</param>
        /// <param name="offset">offset in array</param>
        /// <param name="length">length of block for processing</param>
        protected override void HashCore(byte[] array, int offset, int length)
        {
            int currentOffset = offset;
            int currentLength = length;

            if (lastBlockLength > 0)
            {
                Buffer.BlockCopy(
                    array, currentOffset,
                    lastBlock, lastBlockLength,
                    lastBlock.Length - lastBlockLength
                    );

                ProcessBlock(lastBlock, 0);

                currentOffset += lastBlockLength;
                currentLength -= lastBlockLength;

                lastBlockLength = 0;
            }

            int blockCount = currentLength / BlockSize;
            lastBlockLength = currentLength % BlockSize;

            for (int ii = 0; ii < blockCount; ii++, currentOffset += BlockSize)
                ProcessBlock(array, currentOffset);

            if (lastBlockLength != 0)
                Buffer.BlockCopy(
                    array, currentOffset,
                    lastBlock, 0,
                    lastBlockLength);
        }

        /// <summary>
        /// Hash final block.
        /// </summary>
        /// <returns>hash value</returns>
        protected override byte[] HashFinal()
        {
            ProcessFinalBlock(lastBlock, 0, lastBlockLength);

            return Result;
        }

        #endregion
    }
}
