using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_512Benchmark
    {
        private System.Security.Cryptography.SHA512 cryptoProviderImpl = System.Security.Cryptography.SHA512.Create();

        private System.Security.Cryptography.SHA512Managed systemManagedImpl = new System.Security.Cryptography.SHA512Managed();

        private global::acryptohashnet.Sha2_512 sha2_512AcryptohashnetImpl = new global::acryptohashnet.Sha2_512();

        private global::acryptohashnet.Sha3_512 sha3_512AcryptohashnetImpl = new global::acryptohashnet.Sha3_512();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha2_512CryptoProvider() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_512SystemManaged() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_512AcryptoHashNet() => sha2_512AcryptohashnetImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_512AcryptoHashNet() => sha3_512AcryptohashnetImpl.ComputeHash(Input);
    }
}
