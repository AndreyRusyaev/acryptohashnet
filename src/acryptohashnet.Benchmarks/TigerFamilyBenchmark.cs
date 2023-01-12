using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class TigerFamilyBenchmark
    {
        private global::acryptohashnet.SHA1 sha1Impl = new global::acryptohashnet.SHA1();

        private global::acryptohashnet.Tiger tigerImpl = new global::acryptohashnet.Tiger();

        private global::acryptohashnet.Tiger2 tiger2Impl = new global::acryptohashnet.Tiger2();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] SHA1Impl() => sha1Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] TigerImpl() => tigerImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Tiger2Impl() => tiger2Impl.ComputeHash(Input);
    }
}
