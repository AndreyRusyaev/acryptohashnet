using System;

namespace Home.Andir.Cryptography
{
    public sealed class BigCounter
    {
        private readonly int sizeInBytes;
        private readonly uint[] array;

        public BigCounter(int sizeInBytes)
        {
            this.sizeInBytes = sizeInBytes;

            var sizeInUints = sizeInBytes / 4;
            if (sizeInBytes % 4 > 0)
            {
                sizeInUints += 1;
            }

            array = new uint[sizeInUints];
        }

        public void Clear()
        {
            Array.Clear(array, 0, array.Length);
        }

        public void Add(int value)
        {
            Add((uint)value);
        }

        public void Add(uint value)
        {
            Add(0, value);
        }

        public void Add(long value)
        {
            uint[] values = new uint[2];

            values[0] = (uint)value;
            values[1] = (uint)(value >> 32);

            Add(values);
        }

        private void Add(uint[] input)
        {
            int maxIndex = Math.Min(array.Length, input.Length);
            for (int ii = 0; ii < maxIndex; ii++)
            {
                Add(ii, input[ii]);
            }
        }

        private void Add(int index, uint value)
        {
            if (value > uint.MaxValue - array[index])
            {
                array[index] = uint.MaxValue - array[index];
                array[index] += 1;
                array[index] = value - array[index];

                if (index + 1 >= array.Length)
                {
                    throw new OverflowException("counter overflow!");
                }

                Add(index + 1, 1);
            }
            else
            {
                array[index] += value;
            }
        }

        public byte[] GetBytes()
        {
            byte[] result = new byte[sizeInBytes];

            Buffer.BlockCopy(array, 0, result, 0, result.Length);

            return result;
        }

        public uint ToUInt32()
        {
            return array[0];
        }

        public ulong ToULong()
        {
            return (((ulong)array[1]) << 32) + array[0];
        }
    }
}
