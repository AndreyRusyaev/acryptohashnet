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
        public void BufferBlockCopyToUInt32() => System.Buffer.BlockCopy(Bytes, 0, UInt32s, 0, Bytes.Length);

        [Benchmark]
        public void LittleEndianCopyToUInt32() => LittleEndian.Copy(Bytes, UInt32s);

        [Benchmark]
        public void BigEndianCopyToUInt32() => BigEndian.Copy(Bytes, UInt32s);
    }
}
