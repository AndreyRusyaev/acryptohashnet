using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class BigEndianCopyFromUInt64Benchmark
    {
        public ulong UInt64Input { get; set; }

        public byte[] Bytes { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            UInt64Input = 0x1F2E3D4C5B6A7887UL;
            Bytes = new byte[8];
        }

        [Benchmark]
        public void BigEndianBench()
        {
            BigEndian.Copy(UInt64Input, Bytes);
        }

        [Benchmark]
        public void SeveralShifts()
        {
            var input = UInt64Input;
            var bytes = Bytes;

            bytes[7] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[6] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[5] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[4] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[3] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[2] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[1] = unchecked((byte)(input & 0xff));
            input >>= 8;
            bytes[0] = unchecked((byte)(input & 0xff));
        }

        [Benchmark]
        public void SeveralShiftsWithoutUnchecked()
        {
            var input = UInt64Input;
            var bytes = Bytes;

            bytes[7] = (byte)(input & 0xff);
            input >>= 8;
            bytes[6] = (byte)(input & 0xff);
            input >>= 8;
            bytes[5] = (byte)(input & 0xff);
            input >>= 8;
            bytes[4] = (byte)(input & 0xff);
            input >>= 8;
            bytes[3] = (byte)(input & 0xff);
            input >>= 8;
            bytes[2] = (byte)(input & 0xff);
            input >>= 8;
            bytes[1] = (byte)(input & 0xff);
            input >>= 8;
            bytes[0] = (byte)(input & 0xff);
        }

        [Benchmark]
        public void SeveralShiftsInCycle()
        {
            var input = UInt64Input;
            var bytes = Bytes;

            for (int ii = 0; ii < 8 && ii < Bytes.Length; ii++)
            {
                bytes[7 - ii] = unchecked((byte)(input & 0xff));
                input >>= 8;
            }
        }

        [Benchmark]
        public void OneShiftAnds()
        {
            var input = UInt64Input;
            var bytes = Bytes;

            bytes[0] = (byte)(input >> 56);
            bytes[1] = (byte)(input >> 48);
            bytes[2] = (byte)(input >> 40);
            bytes[3] = (byte)(input >> 32);
            bytes[4] = (byte)(input >> 24);
            bytes[5] = (byte)(input >> 16);
            bytes[6] = (byte)(input >> 8);
            bytes[7] = (byte)input;
        }

        [Benchmark]
        public void OneShiftAndsUnchecked()
        {
            var input = UInt64Input;
            var bytes = Bytes;

            bytes[0] = unchecked((byte)((input >> 56) & 0xff));
            bytes[1] = unchecked((byte)((input >> 48) & 0xff));
            bytes[2] = unchecked((byte)((input >> 40) & 0xff));
            bytes[3] = unchecked((byte)((input >> 32) & 0xff));
            bytes[4] = unchecked((byte)((input >> 24) & 0xff));
            bytes[5] = unchecked((byte)((input >> 16) & 0xff));
            bytes[6] = unchecked((byte)((input >> 8) & 0xff));
            bytes[7] = unchecked((byte)(input & 0xff));
        }
    }
}
