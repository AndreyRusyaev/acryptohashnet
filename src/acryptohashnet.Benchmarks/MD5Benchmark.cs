using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
        public byte[] SystemCryptoProvider() => cryptoProviderImpl.ComputeHash(Input);

        [Benchmark]
        public byte[] AcryptoHashNetImpl() => acryptohashnetImpl.ComputeHash(Input);
    }
}
