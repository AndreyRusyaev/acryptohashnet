using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class MD2Benchmark
    {
        private global::acryptohashnet.MD2 md2Impl = new global::acryptohashnet.MD2();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] MD2Impl() => md2Impl.ComputeHash(Input);
    }
}
