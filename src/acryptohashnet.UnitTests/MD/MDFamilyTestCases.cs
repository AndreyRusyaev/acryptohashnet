using System.Collections.Generic;

namespace acryptohashnet.UnitTests
{
    internal static class MDFamilyTestCases
    {
        public static IEnumerable<HashTestCase> All()
        {
            return new[]
            {
                new HashTestCase
                {
                    Input = "",
                    Md2 = "8350e5a3e24c153df2275c9f80692773",
                    Md4 = "31d6cfe0d16ae931b73c59d7e0c089c0",
                    Md5 = "d41d8cd98f00b204e9800998ecf8427e",
                },

                new HashTestCase
                {
                    Input = "a",
                    Md2 = "32ec01ec4a6dac72c0ab96fb34c0b5d1",
                    Md4 = "bde52cb31de33e46245e05fbdbd6fb24",
                    Md5 = "0cc175b9c0f1b6a831c399e269772661",
                },

                new HashTestCase
                {
                    Input = "abc",
                    Md2 = "da853b0d3f88d99b30283a69e6ded6bb",
                    Md4 = "a448017aaf21d8525fc10ae87aa6729d",
                    Md5 = "900150983cd24fb0d6963f7d28e17f72",
                },

                new HashTestCase
                {
                    Input = "message digest",
                    Md2 = "ab4f496bfb2a530b219ff33031fe06b0",
                    Md4 = "d9130a8164549fe818874806e1c7014b",
                    Md5 = "f96b697d7cb7938d525a2f31aaf161d0",
                },

                new HashTestCase
                {
                    Input = "abcdefghijklmnopqrstuvwxyz",
                    Md2 = "4e8ddff3650292ab5a4108c3aa47940b",
                    Md4 = "d79e1c308aa5bbcdeea8ed63df412da9",
                    Md5 = "c3fcd3d76192e4007dfb496cca67e13b",
                },

                new HashTestCase
                {
                    Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    Md2 = "da33def2a42df13975352846c30338cd",
                    Md4 = "043f8582f241db351ce627e153e7f0e4",
                    Md5 = "d174ab98d277d9f5a5611c2c9f419d9f",
                },

                new HashTestCase
                {
                    Input = "For this sample, this 63-byte string will be used as input data",
                    Md2 = "4d2b317fb976ad61b23eaf8fe8592bcf",
                    Md4 = "0b501fa8881a5caa0d83fe7a3d2d186d",
                    Md5 = "b02752d13a05fa8d7d04aabd158ff9d1",
                },

                new HashTestCase
                {
                    Input = "This is exactly 64 bytes long, not counting the terminating byte",
                    Md2 = "6caa9cd8554a2152f201f9705d7027a6",
                    Md4 = "572c146781d8abc6d5f827844cf4d94b",
                    Md5 = "debcb70bf9c8e83659ef1d85aa51c5e9",
                },

                new HashTestCase
                {
                    Input = "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                    Md2 = "303a4941ba2a3fb01430289503d074ee",
                    Md4 = "0c1d5450ebdf236aceee8b0b66cdfa72",
                    Md5 = "50c757c2522680444582b8f4572b32f2",
                },

                new HashTestCase
                {
                    Input = "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                    Md2 = "0b4e8940897149509fd7bc5078032578",
                    Md4 = "dadc76e37d7b36b2e313a13657ac5f9f",
                    Md5 = "268dc47e6b6f19a86481374b2ced6f18",
                },

                new HashTestCase
                {
                    Input = "Exactly 1000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX",
                    Md2 = "cbede9d6080aea700605ad4565a9e3af",
                    Md4 = "0fc4c9f881efddbd5712c8a52d4f5271",
                    Md5 = "8552d46f34d75f4f770ea10227d73cb9",
                },

                new HashTestCase
                {
                    Input = "Exactly 4000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl",
                    Md2 = "518453006c8c5a4f389d722322186099",
                    Md4 = "a273308cf00e3b57839733972abeefd3",
                    Md5 = "2f5d1fb0a5a7281d92333b1012719965",
                },

                new HashTestCase
                {
                    Input = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                    Md2 = "58bacf68f1f8ed5a3515ae0607b3b511",
                    Md4 = "50385e2a1f0b9869040a289eff3abff2",
                    Md5 = "43696c3abe0610e776cde9bf4c052421",
                }
            };
        }

        internal record HashTestCase
        {
            public string Input { get; init; } = default!;

            public string Md2 { get; init; } = default!;

            public string Md4 { get; init; } = default!;

            public string Md5 { get; init; } = default!;
        }
    }
}
