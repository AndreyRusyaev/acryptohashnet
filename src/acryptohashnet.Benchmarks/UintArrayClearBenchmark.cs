using System;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class UintArrayClearBenchmark
    {
        public uint[] Buffer { get; set; }

        [Params(16, 64, 128, 256)]
        public int BufferSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Buffer = new uint[BufferSize];
        }

        [Benchmark]
        public void ArrayClear() => Array.Clear(Buffer, 0, Buffer.Length);

        [Benchmark]
        public void ManualZeroSet()
        {
            for (int ii = 0; ii < Buffer.Length; ii++)
            {
                Buffer[ii] = 0;
            }
        }
    }
}
