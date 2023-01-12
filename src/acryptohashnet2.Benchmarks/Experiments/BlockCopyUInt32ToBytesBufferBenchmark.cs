using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class BlockCopyUInt32ToBytesBufferBenchmark
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
        public void BufferBlockCopyFromUInt64() => System.Buffer.BlockCopy(UInt32s, 0, Bytes, 0, Bytes.Length);

        [Benchmark]
        public void LittleEndianCopyFromUInt64() => LittleEndian.Copy(UInt32s, Bytes);

        [Benchmark]
        public void BigEndianCopyFromUInt64() => BigEndian.Copy(UInt32s, Bytes);
    }
}
