using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class BlockCopyBytesToUInt32BufferBenchmark
    {
        public byte[] Bytes { get; set; }

        public uint[] UInt32s { get; set; }


        [Params(4, 8, 16, 64, 128, 256, 512, 1024)]
        public int BytesBufferSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Bytes = new byte[BytesBufferSize];
            UInt32s = new uint[BytesBufferSize / 4];
        }

        [Benchmark]
        public void BufferBlockCopyUInt32() => System.Buffer.BlockCopy(Bytes, 0, UInt32s, 0, Bytes.Length);

        [Benchmark]
        public void BigEndianBufferBlockCopyUInt32() => BigEndianBuffer.BlockCopy(Bytes, 0, UInt32s, 0, Bytes.Length);
    }
}
