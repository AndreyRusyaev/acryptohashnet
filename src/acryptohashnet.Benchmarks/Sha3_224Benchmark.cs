using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_224Benchmark
    {
        private System.Security.Cryptography.SHA256 cryptoProviderImpl = System.Security.Cryptography.SHA256.Create();

        private System.Security.Cryptography.SHA256Managed systemManagedImpl = new System.Security.Cryptography.SHA256Managed();

        private global::acryptohashnet.Sha3_224 acryptohashnetImpl = new global::acryptohashnet.Sha3_224();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha256CryptoProviderImpl() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha256SystemManagedImpl() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_224AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
