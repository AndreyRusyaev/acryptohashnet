using BenchmarkDotNet.Attributes;
using System;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class ArrayCopyBenchmark
    {
        public byte[] Input { get; set; }

        public byte[] Output { get; set; }

        [Params(0, 1, 4, 8, 16, 64, 128, 256, 512, 1024)]
        public int BufferSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Input = new byte[BufferSize];
            Output = new byte[BufferSize];
        }

        [Benchmark]
        public void ArrayCopy() => System.Array.Copy(Input, 0, Output, 0, Output.Length);

        [Benchmark]
        public void ArrayCopyTo() => Input.CopyTo(Output, 0);

        [Benchmark]
        public void SpanCopyTo() => Input.AsSpan().CopyTo(Output);

        [Benchmark]
        public void BufferCopy() => System.Buffer.BlockCopy(Input, 0, Output, 0, Output.Length);

        [Benchmark]
        public void ManualCopy()
        {
            for(int ii = 0; ii < Output.Length && ii < Input.Length; ii++)
            {
                Output[ii] = Input[ii];
            }
        }
    }
}
