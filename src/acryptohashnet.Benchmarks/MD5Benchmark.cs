using System.Collections.Generic;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class MD5Benchmark
    {
        private System.Security.Cryptography.MD5 cryptoProviderImpl = System.Security.Cryptography.MD5.Create();

        private global::acryptohashnet.MD5 acryptohashnetImpl = new global::acryptohashnet.MD5();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource { get; } = TestSuite.BinaryMessages;

        [Benchmark]
        public byte[] SystemCryptoProvider() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
