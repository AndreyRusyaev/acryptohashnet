using BenchmarkDotNet.Attributes;
using System;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class ArrayClearBenchmark
    {
        public byte[] Bytes { get; set; }

        public uint[] UInt32s { get; set; }

        [Params(0, 1, 4, 8, 16, 64, 128, 256, 512, 1024)]
        public int BufferSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Bytes = new byte[BufferSize];
            UInt32s = new uint[BufferSize];
        }

        [Benchmark]
        public void ArrayClearUInt8() => System.Array.Clear(Bytes, 0, Bytes.Length);

        [Benchmark]
        public void ArrayAsSpanClearUInt8() => Bytes.AsSpan().Clear();

        [Benchmark]
        public void ManualZeroSetUInt8()
        {
            for (int ii = 0; ii < Bytes.Length; ii++)
            {
                Bytes[ii] = 0;
            }
        }

        [Benchmark]
        public void ArrayClearUInt32() => System.Array.Clear(UInt32s, 0, UInt32s.Length);

        [Benchmark]
        public void ArrayAsSpanClearUInt32() => UInt32s.AsSpan().Clear();

        [Benchmark]
        public void ManualZeroSetUInt32()
        {
            for (int ii = 0; ii < UInt32s.Length; ii++)
            {
                UInt32s[ii] = 0;
            }
        }
    }
}
