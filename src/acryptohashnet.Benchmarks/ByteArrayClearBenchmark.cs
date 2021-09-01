using System;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class ByteArrayClearBenchmark
    {
        public byte[] Block { get; set; }

        [Params(16, 64, 128, 256)]
        public int BlockSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Block = new byte[BlockSize];
        }

        [Benchmark]
        public void ByteArrayClear() => Array.Clear(Block, 0, Block.Length);

        [Benchmark]
        public void ByteManualZeroSet()
        {
            for (int ii = 0; ii < Block.Length; ii++)
            {
                Block[ii] = 0;
            }
        }
    }
}
