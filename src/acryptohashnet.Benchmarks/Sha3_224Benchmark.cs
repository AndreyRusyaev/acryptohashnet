using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class Sha3_224Benchmark
    {
        private System.Security.Cryptography.SHA256 cryptoProviderImpl = System.Security.Cryptography.SHA256.Create();

        private System.Security.Cryptography.SHA256Managed systemManagedImpl = new System.Security.Cryptography.SHA256Managed();

        private global::acryptohashnet.Sha2_224 sha2_224AcryptohashnetImpl = new global::acryptohashnet.Sha2_224();

        private global::acryptohashnet.Sha3_224 sha3_224AcryptohashnetImpl = new global::acryptohashnet.Sha3_224();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] Sha256CryptoProvider() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha256SystemManaged() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha2_224AcryptoHashNet() => sha2_224AcryptohashnetImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] Sha3_224AcryptoHashNet() => sha3_224AcryptohashnetImpl.ComputeHash(Input);
    }
}
