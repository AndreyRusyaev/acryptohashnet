using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_512Benchmark
    {
        private System.Security.Cryptography.SHA512 cryptoProviderImpl = System.Security.Cryptography.SHA512.Create();

        private System.Security.Cryptography.SHA512Managed systemManagedImpl = new System.Security.Cryptography.SHA512Managed();

        private global::acryptohashnet.Sha3_512 acryptohashnetImpl = new global::acryptohashnet.Sha3_512();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha2_512CryptoProviderImpl() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_512SystemManagedImpl() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_512AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
