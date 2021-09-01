using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class UlongBlockCopyBenchmark
    {
        public byte[] Block { get; set; }

        public ulong[] Buffer { get; set; }

        [Params(16, 64, 128, 256)]
        public int BlockSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Block = new byte[BlockSize];
            Buffer = new ulong[BlockSize / 8];
        }

        [Benchmark]
        public void BufferBlockCopy() => System.Buffer.BlockCopy(Block, 0, Buffer, 0, Buffer.Length);

        [Benchmark]
        public void BigEndianBufferBlockCopy() => BigEndianBuffer.BlockCopy(Block, 0, Buffer, 0, Buffer.Length);
    }
}
