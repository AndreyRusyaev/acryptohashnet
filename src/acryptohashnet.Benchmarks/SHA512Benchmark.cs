using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
