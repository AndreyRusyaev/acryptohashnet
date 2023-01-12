using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class SHA1Benchmark
    {
        private System.Security.Cryptography.SHA1 cryptoProviderImpl = System.Security.Cryptography.SHA1.Create();

        private System.Security.Cryptography.SHA1Managed systemManagedImpl = new System.Security.Cryptography.SHA1Managed();

        private global::acryptohashnet.SHA1 acryptohashnetImpl = new global::acryptohashnet.SHA1();

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
