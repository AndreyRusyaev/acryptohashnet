using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class UintBlockCopyBenchmark
    {
        public byte[] Block { get; set; }

        public uint[] Buffer { get; set; }

        [Params(16, 64, 128, 256)]
        public int BlockSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Block = new byte[BlockSize];
            Buffer = new uint[BlockSize / 4];
        }

        [Benchmark]
        public void BufferBlockCopy() => System.Buffer.BlockCopy(Block, 0, Buffer, 0, Buffer.Length);

        [Benchmark]
        public void BigEndianBufferBlockCopy() => BigEndianBuffer.BlockCopy(Block, 0, Buffer, 0, Buffer.Length);
    }
}
