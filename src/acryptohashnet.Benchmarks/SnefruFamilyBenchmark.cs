using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class SnefruFamilyBenchmark
    {
        private global::acryptohashnet.SHA1 sha1Impl = new global::acryptohashnet.SHA1();

        private global::acryptohashnet.Snefru snefruImpl = new global::acryptohashnet.Snefru();

        private global::acryptohashnet.Snefru256 snefru256Impl = new global::acryptohashnet.Snefru256();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] SHA1Impl() => sha1Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] SnefruImpl() => snefruImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Snefru256Impl() => snefru256Impl.ComputeHash(Input);
    }
}
