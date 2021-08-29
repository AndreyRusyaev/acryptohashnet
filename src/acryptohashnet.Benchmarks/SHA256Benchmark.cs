using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using BenchmarkDotNet.Attributes;

namespace acryptohashnet.Benchmarks
{
    [MemoryDiagnoser]
    public class SHA256Benchmark
    {
        private System.Security.Cryptography.SHA256 cryptoProviderImpl = System.Security.Cryptography.SHA256.Create();

        private System.Security.Cryptography.SHA256Managed systemManagedImpl = new System.Security.Cryptography.SHA256Managed();

        private global::acryptohashnet.SHA256 acryptohashnetImpl = new global::acryptohashnet.SHA256();

        [ParamsSource(nameof(InputSource))]
        public byte[] Input { get; set; }

        public IEnumerable<byte[]> InputSource
        {
            get
            {
                string[] inputs = new string[]
                {
                    "",
                    "a",
                    "abc",
                    "message digest",
                    "abcdefghijklmnopqrstuvwxyz",
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    "12345678901234567890123456789012345678901234567890123456789012345678901234567890"
                };

                return inputs.Select(x => Encoding.UTF8.GetBytes(x));
            }
        }

        [Benchmark]
        public byte[] CryptoProviderImpl() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] SystemManagedImpl() => systemManagedImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
