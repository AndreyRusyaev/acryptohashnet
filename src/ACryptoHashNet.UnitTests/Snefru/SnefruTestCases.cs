using System.Collections.Generic;

namespace acryptohashnet.UnitTests
{
    internal static class SnefruTestCases
    {
        public static IEnumerable<HashTestCase> All()
        {
            return new[]
            {
                new HashTestCase
                {
                    Input = "a",
                    Snefru = "bf5ce540ae51bc50399f96746c5a15bd",
                    Snefru256 = "45161589ac317be0ceba70db2573ddda6e668a31984b39bf65e4b664b584c63d"
                },

                new HashTestCase
                {
                    Input = "abc",
                    Snefru = "553d0648928299a0f22a275a02c83b10",
                    Snefru256 = "7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b"
                },

                new HashTestCase
                {
                    Input = "message digest",
                    Snefru = "96d6f2f4112c4baf29f653f1594e2d5d",
                    Snefru256 = "c5d4ce38daa043bdd59ed15db577500c071b917c1a46cd7b4d30b44a44c86df8"
                },

                new HashTestCase
                {
                    Input = "abcdefghijklmnopqrstuvwxyz",
                    Snefru = "7840148a66b91c219c36f127a0929606",
                    Snefru256 = "9304bb2f876d9c4f54546cf7ec59e0a006bead745f08c642f25a7c808e0bf86e"
                },

                new HashTestCase
                {
                    Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    Snefru = "0efd7f93a549f023b79781090458923e",
                    Snefru256 = "83aa9193b62ffd269faa43d31e6ac2678b340e2a85849470328be9773a9e5728"
                },

                new HashTestCase
                {
                    Input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
                    Snefru = "d9204ed80bb8430c0b9c244fe485814a",
                    Snefru256 = "d5fce38a152a2d9b83ab44c29306ee45ab0aed0e38c957ec431dab6ed6bb71b8"
                },

                new HashTestCase
                {
                    Input = "\n",
                    Snefru = "d9fcb3171c097fbba8c8f12aa0906bad",
                    Snefru256 = "2e02687f0d45d5b9b50cb68c3f33e6843d618a1aca2d06893d3eb4e3026b5732"
                },

                new HashTestCase
                {
                    Input = "1\n",
                    Snefru = "44ec420ce99c1f62feb66c53c24ae453",
                    Snefru256 = "bfea4a05a2a2ef15c736d114598a20b9d9bd4d66b661e6b05ecf6a7737bdc58c"
                },

                new HashTestCase
                {
                    Input = "12\n",
                    Snefru = "7182051aa852ef6fba4b6c9c9b79b317",
                    Snefru256 = "ac677d69761ade3f189c7aef106d5fe7392d324e19cc76d5db4a2c05f2cc2cc5"
                },

                new HashTestCase
                {
                    Input = "123\n",
                    Snefru = "bc3a50af82bf56d6a64732bc7b050a93",
                    Snefru256 = "061c76aa1db4a22c0e42945e26c48499b5400162e08c640be05d3c007c44793d"
                },

                new HashTestCase
                {
                    Input = "1234\n",
                    Snefru = "c5b8a04985a8eadfb4331a8988752b77",
                    Snefru256 = "1e87fe1d9c927e9e24be85e3cc73359873541640a6261793ce5a974953113f5e"
                },

                new HashTestCase
                {
                    Input = "12345\n",
                    Snefru = "d559a2b62f6f44111324f85208723707",
                    Snefru256 = "1b59927d85a9349a87796620fe2ff401a06a7ba48794498ebab978efc3a68912"
                },

                new HashTestCase
                {
                    Input = "123456\n",
                    Snefru = "6cfb5e8f1da02bd167b01e4816686c30",
                    Snefru256 = "28e9d9bc35032b68faeda88101ecb2524317e9da111b0e3e7094107212d9cf72"
                },

                new HashTestCase
                {
                    Input = "1234567\n",
                    Snefru = "29aa48325f275a8a7a01ba1543c54ba5",
                    Snefru256 = "f7fff4ee74fd1b8d6b3267f84e47e007f029d13b8af7e37e34d13b469b8f248f"
                },

                new HashTestCase
                {
                    Input = "12345678\n",
                    Snefru = "be862a6b68b7df887ebe00319cbc4a47",
                    Snefru256 = "ee7d64b0102b2205e98926613b200185559d08be6ad787da717c968744e11af3"
                },

                new HashTestCase
                {
                    Input = "123456789\n",
                    Snefru = "6103721ccd8ad565d68e90b0f8906163",
                    Snefru256 = "4ca72639e40e9ab9c0c3f523c4449b3911632d374c124d7702192ec2e4e0b7a3"
                }
            };
        }

        internal record HashTestCase
        {
            public string Input { get; init; } = default!;

            public string Snefru { get; init; } = default!;

            public string Snefru256 { get; init; } = default!;
        }
    }
}
