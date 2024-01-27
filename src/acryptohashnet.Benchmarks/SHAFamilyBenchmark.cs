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

        private global::acryptohashnet.Sha2_224 sha2_224Impl = new global::acryptohashnet.Sha2_224();

        private global::acryptohashnet.Sha2_256 sha2_256Impl = new global::acryptohashnet.Sha2_256();

        private global::acryptohashnet.Sha2_384 sha2_384Impl = new global::acryptohashnet.Sha2_384();

        private global::acryptohashnet.Sha2_512 sha2_512Impl = new global::acryptohashnet.Sha2_512();

        private global::acryptohashnet.Sha3_224 sha3_224Impl = new global::acryptohashnet.Sha3_224();

        private global::acryptohashnet.Sha3_256 sha3_256Impl = new global::acryptohashnet.Sha3_256();

        private global::acryptohashnet.Sha3_384 sha3_384Impl = new global::acryptohashnet.Sha3_384();

        private global::acryptohashnet.Sha3_512 sha3_512Impl = new global::acryptohashnet.Sha3_512();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha0Impl() => sha0Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha1Impl() => sha1Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_224Impl() => sha2_224Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_256Impl() => sha2_256Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_384Impl() => sha2_384Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_512Impl() => sha2_512Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_224Impl() => sha3_224Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_256Impl() => sha3_256Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_384Impl() => sha3_384Impl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_512Impl() => sha3_512Impl.ComputeHash(Input);
    }
}
