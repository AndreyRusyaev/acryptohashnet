using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class RIPEMDFamilyBenchmark
    {
        private global::acryptohashnet.SHA1 sha1Impl = new global::acryptohashnet.SHA1();

        private global::acryptohashnet.RIPEMD128 ripeMd128Impl = new global::acryptohashnet.RIPEMD128();

        private global::acryptohashnet.RIPEMD160 ripeMd160Impl = new global::acryptohashnet.RIPEMD160();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] SHA1Impl() => sha1Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] TigerImpl() => ripeMd128Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Tiger2Impl() => ripeMd160Impl.ComputeHash(Input);
    }
}
