using System.Collections.Generic;

namespace acryptohashnet.UnitTests
{
    internal static class RIPEMDFamilyTestCases
    {
        public static IEnumerable<HashTestCase> All()
        {
            return new[]
            {
                new HashTestCase
                {
                    Input = "",
                    RipeMd128 = "cdf26213a150dc3ecb610f18f6b38b46",
                    RipeMd160 = "9c1185a5c5e9fc54612808977ee8f548b2258d31",
                },

                new HashTestCase
                {
                    Input = "a",
                    RipeMd128 = "86be7afa339d0fc7cfc785e72f578d33",
                    RipeMd160 = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe",
                },

                new HashTestCase
                {
                    Input = "abc",
                    RipeMd128 = "c14a12199c66e4ba84636b0f69144c77",
                    RipeMd160 = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
                },

                new HashTestCase
                {
                    Input = "message digest",
                    RipeMd128 = "9e327b3d6e523062afc1132d7df9d1b8",
                    RipeMd160 = "5d0689ef49d2fae572b881b123a85ffa21595f36",
                },

                new HashTestCase
                {
                    Input = "abcdefghijklmnopqrstuvwxyz",
                    RipeMd128 = "fd2aa607f71dc8f510714922b371834e",
                    RipeMd160 = "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
                },

                new HashTestCase
                {
                    Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    RipeMd128 = "d1e959eb179c911faea4624c60c5c702",
                    RipeMd160 = "b0e20b6e3116640286ed3a87a5713079b21f5189",
                },

                new HashTestCase
                {
                    Input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                    RipeMd128 = "3f45ef194732c2dbb2c4a2c769795fa3",
                    RipeMd160 = "9b752e45573d4b39f4dbd3323cab82bf63326bfb",
                },
            };
        }

        internal record HashTestCase
        {
            public string Input { get; init; } = default!;

            public string RipeMd128 { get; init; } = default!;

            public string RipeMd160 { get; init; } = default!;
        }
    }
}
