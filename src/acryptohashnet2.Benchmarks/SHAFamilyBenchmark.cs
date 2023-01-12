using System;
using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class SHAFamilyBenchmark
    {
        private global::acryptohashnet.SHA0 sha0Impl = new global::acryptohashnet.SHA0();

        private global::acryptohashnet.SHA1 sha1Impl = new global::acryptohashnet.SHA1();

        private global::acryptohashnet.SHA256 sha256Impl = new global::acryptohashnet.SHA256();

        private global::acryptohashnet.SHA384 sha384Impl = new global::acryptohashnet.SHA384();

        private global::acryptohashnet.SHA512 sha512Impl = new global::acryptohashnet.SHA512();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha0Impl() => sha0Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha1Impl() => sha1Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha256Impl() => sha256Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha384Impl() => sha384Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha512Impl() => sha512Impl.ComputeHash(Input);
    }
}
