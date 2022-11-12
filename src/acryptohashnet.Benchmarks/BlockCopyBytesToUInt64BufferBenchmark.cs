﻿using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class BlockCopyBytesToUInt64BufferBenchmark
    {
        public byte[] Bytes { get; set; }

        public ulong[] UInt64s { get; set; }


        [Params(8, 16, 64, 128, 256, 512, 1024)]
        public int BytesBufferSize { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            Bytes = new byte[BytesBufferSize];
            UInt64s = new ulong[BytesBufferSize / 8];
        }

        [Benchmark]
        public void BufferBlockCopyUInt64() => System.Buffer.BlockCopy(Bytes, 0, UInt64s, 0, Bytes.Length);

        [Benchmark]
        public void BigEndianBufferBlockCopyUInt64() => BigEndianBuffer.BlockCopy(Bytes, 0, UInt64s, 0, Bytes.Length);
    }
}