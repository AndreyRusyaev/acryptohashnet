using BenchmarkDotNet.Attributes;
using System;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class BigEndianCopyToUInt64Benchmark
    {
        public byte[] Bytes { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Bytes = new byte[] { 0x1F, 0x2E, 0x3D, 0x4C, 0x5B, 0x6A, 0x78, 0x87 };            
        }

        [Benchmark]
        public ulong BigEndianBench()
        {
            return BigEndian.ToUInt64(Bytes);
        }

        [Benchmark]
        public ulong SeveralShifts()
        {
            ulong result = Bytes[0];
            result = unchecked(result << 8 | Bytes[1]);
            result = unchecked(result << 8 | Bytes[2]);
            result = unchecked(result << 8 | Bytes[3]);
            result = unchecked(result << 8 | Bytes[4]);
            result = unchecked(result << 8 | Bytes[5]);
            result = unchecked(result << 8 | Bytes[6]);
            result = unchecked(result << 8 | Bytes[7]);
            return result;
        }

        [Benchmark]
        public ulong SeveralShiftsInCycle()
        {
            ulong result = 0;
            for (int ii = 0; ii < 8 && ii < Bytes.Length; ii++)
            {
                result = unchecked(result << 8 | Bytes[ii]);
            }
            return result;
        }

        [Benchmark]
        public ulong OneShiftAnds()
        {
            ulong result = (ulong)Bytes[0] << 56
                | (ulong)Bytes[1] << 48
                | (ulong)Bytes[2] << 40
                | (ulong)Bytes[3] << 32
                | (ulong)Bytes[4] << 24
                | (ulong)Bytes[5] << 16
                | (ulong)Bytes[6] << 8
                | (ulong)Bytes[7];
            return result;
        }

        [Benchmark]
        public ulong OneShiftAndsUnchecked()
        {
            ulong result = unchecked((ulong)Bytes[0] << 56)
                | unchecked((ulong)Bytes[1] << 48)
                | unchecked((ulong)Bytes[2] << 40)
                | unchecked((ulong)Bytes[3] << 32)
                | unchecked((ulong)Bytes[4] << 24)
                | unchecked((ulong)Bytes[5] << 16)
                | unchecked((ulong)Bytes[6] << 8)
                | unchecked((ulong)Bytes[7]);
            return result;
        }
    }
}
