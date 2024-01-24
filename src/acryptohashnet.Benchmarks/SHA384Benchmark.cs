using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class SHA384Benchmark
    {
        private System.Security.Cryptography.SHA384 cryptoProviderImpl = System.Security.Cryptography.SHA384.Create();

        private System.Security.Cryptography.SHA384Managed systemManagedImpl = new System.Security.Cryptography.SHA384Managed();

        private global::acryptohashnet.Sha2_384 acryptohashnetImpl = new global::acryptohashnet.Sha2_384();

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
