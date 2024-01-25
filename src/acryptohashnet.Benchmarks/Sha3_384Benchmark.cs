using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_384Benchmark
    {
        private System.Security.Cryptography.SHA384 cryptoProviderImpl = System.Security.Cryptography.SHA384.Create();

        private System.Security.Cryptography.SHA384Managed systemManagedImpl = new System.Security.Cryptography.SHA384Managed();

        private global::acryptohashnet.Sha2_384 sha2_384AcryptohashnetImpl = new global::acryptohashnet.Sha2_384();

        private global::acryptohashnet.Sha3_384 sha3_384AcryptohashnetImpl = new global::acryptohashnet.Sha3_384();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha2_384CryptoProvider() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_384SystemManaged() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_384AcryptoHashNet() => sha2_384AcryptohashnetImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_384AcryptoHashNet() => sha3_384AcryptohashnetImpl.ComputeHash(Input);
    }
}
