using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class SHA512Benchmark
    {
        private System.Security.Cryptography.SHA512 cryptoProviderImpl = System.Security.Cryptography.SHA512.Create();

        private System.Security.Cryptography.SHA512Managed systemManagedImpl = new System.Security.Cryptography.SHA512Managed();

        private global::acryptohashnet.SHA512 acryptohashnetImpl = new global::acryptohashnet.SHA512();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] CryptoProviderImpl() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] SystemManagedImpl() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
