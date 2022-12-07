using BenchmarkDotNet.Attributes;
using System.Collections.Generic;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    internal class HavalFamilyBenchmark
    {
        private global::acryptohashnet.Haval128 haval128 = new global::acryptohashnet.Haval128();

        private global::acryptohashnet.Haval160 haval160 = new global::acryptohashnet.Haval160();

        private global::acryptohashnet.Haval192 haval192 = new global::acryptohashnet.Haval192();

        private global::acryptohashnet.Haval224 haval224 = new global::acryptohashnet.Haval224();

        private global::acryptohashnet.Haval256 haval256 = new global::acryptohashnet.Haval256();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Haval128Impl() => haval128.ComputeHash(Input);

        [Benchmark]
        public byte[] Haval160Impl() => haval160.ComputeHash(Input);

        [Benchmark]
        public byte[] Haval192Impl() => haval192.ComputeHash(Input);

        [Benchmark]
        public byte[] Haval224Impl() => haval224.ComputeHash(Input);

        [Benchmark]
        public byte[] Haval256Impl() => haval256.ComputeHash(Input);
    }
}
