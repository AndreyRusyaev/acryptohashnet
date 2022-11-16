using System.Collections.Generic;

namespace acryptohashnet.UnitTests
{
    internal static class TigerTestCases
    {
        public static IEnumerable<HashTestCase> All()
        {
            return new[]
            {
                new HashTestCase
                {
                    Input = "",
                    Tiger = "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3",
                    Tiger2 = "4441be75f6018773c206c22745374b924aa8313fef919f41"
                },

                new HashTestCase
                {
                    Input = "a",
                    Tiger = "77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809",
                    Tiger2 = "67e6ae8e9e968999f70a23e72aeaa9251cbc7c78a7916636"
                },

                new HashTestCase
                {
                    Input = "abc",
                    Tiger = "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93",
                    Tiger2 = "f68d7bc5af4b43a06e048d7829560d4a9415658bb0b1f3bf"
                },

                new HashTestCase
                {
                    Input = "message digest",
                    Tiger = "d981f8cb78201a950dcf3048751e441c517fca1aa55a29f6",
                    Tiger2 = "e29419a1b5fa259de8005e7de75078ea81a542ef2552462d"
                },

                new HashTestCase
                {
                    Input = "abcdefghijklmnopqrstuvwxyz",
                    Tiger = "1714a472eee57d30040412bfcc55032a0b11602ff37beee9",
                    Tiger2 = "f5b6b6a78c405c8547e91cd8624cb8be83fc804a474488fd"
                },

                new HashTestCase
                {
                    Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    Tiger = "8dcea680a17583ee502ba38a3c368651890ffbccdc49a8cc",
                    Tiger2 = "ea9ab6228cee7b51b77544fca6066c8cbb5bbae6319505cd"
                },

                new HashTestCase
                {
                    Input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                    Tiger = "1c14795529fd9f207a958f84c52f11e887fa0cabdfd91bfd",
                    Tiger2 = "d85278115329ebaa0eec85ecdc5396fda8aa3a5820942fff"
                },

                new HashTestCase
                {
                    Input = "Tiger",
                    Tiger = "dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937",
                    Tiger2 = "fe40798b8eb937fd977608930548d6a894c20b04cbef7a42"
                },

                new HashTestCase
                {
                    Input = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham",
                    Tiger = "8a866829040a410c729ad23f5ada711603b3cdd357e4c15e",
                    Tiger2 = "f05589b5b897c0f81f16266f79e3625e0d4d4a4e343e5ef9"
                },

                new HashTestCase
                {
                    Input = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.",
                    Tiger = "ce55a6afd591f5ebac547ff84f89227f9331dab0b611c889",
                    Tiger2 = "d3a2544892a5aec57f03856294a8220a07e7fa11a1618e69"
                },

                new HashTestCase
                {
                    Input = "Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.",
                    Tiger = "631abdd103eb9a3d245b6dfd4d77b257fc7439501d1568dd",
                    Tiger2 = "9a45e77bee2f4d44a751cb36d5ba40c0026dfdff2a7167e0"
                },
            };
        }

        internal record HashTestCase
        {
            public string Input { get; init; } = default!;

            public string Tiger { get; init; } = default!;

            public string Tiger2 { get; init; } = default!;
        }
    }
}
