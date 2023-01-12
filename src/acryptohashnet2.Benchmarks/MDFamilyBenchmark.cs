using System;
using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]    
    public class MDFamilyBenchmark
    {
        private global::acryptohashnet.MD2 md2Impl = new global::acryptohashnet.MD2();

        private global::acryptohashnet.MD4 md4Impl = new global::acryptohashnet.MD4();

        private global::acryptohashnet.MD5 md5Impl = new global::acryptohashnet.MD5();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] MD2Impl() => md2Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] MD4Impl() => md4Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] MD5Impl() => md5Impl.ComputeHash(Input);
    }
}
