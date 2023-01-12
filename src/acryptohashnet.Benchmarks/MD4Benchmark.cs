using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class MD4Benchmark
    {
        private global::acryptohashnet.MD4 md4Impl = new global::acryptohashnet.MD4();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] MD4Impl() => md4Impl.ComputeHash(Input);
    }
}
