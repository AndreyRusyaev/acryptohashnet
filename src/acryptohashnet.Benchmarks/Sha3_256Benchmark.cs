using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_256Benchmark
    {
        private System.Security.Cryptography.SHA256 cryptoProviderImpl = System.Security.Cryptography.SHA256.Create();

        private System.Security.Cryptography.SHA256Managed systemManagedImpl = new System.Security.Cryptography.SHA256Managed();

        private global::acryptohashnet.Sha2_256 sha2_256AcryptohashnetImpl = new global::acryptohashnet.Sha2_256();

        private global::acryptohashnet.Sha3_256 sha3_256AcryptohashnetImpl = new global::acryptohashnet.Sha3_256();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha2_256CryptoProvider() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_256SystemManaged() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_256AcryptoHashNet() => sha2_256AcryptohashnetImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_256AcryptoHashNet() => sha3_256AcryptohashnetImpl.ComputeHash(Input);
    }
}
