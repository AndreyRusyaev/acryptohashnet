using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_256Benchmark
    {
        private System.Security.Cryptography.SHA256 cryptoProviderImpl = System.Security.Cryptography.SHA256.Create();

        private System.Security.Cryptography.SHA256Managed systemManagedImpl = new System.Security.Cryptography.SHA256Managed();

        private global::acryptohashnet.Sha3_256 acryptohashnetImpl = new global::acryptohashnet.Sha3_256();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha2_256CryptoProviderImpl() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_256SystemManagedImpl() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_256AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
