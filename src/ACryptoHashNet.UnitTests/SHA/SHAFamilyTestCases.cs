using System.Collections.Generic;

namespace acryptohashnet.UnitTests
{
    internal static class SHAFamilyTestCases
    {
        public static IEnumerable<HashTestCase> All()
        {
            return new[]
            {
                new HashTestCase
                {
                    Input = "",
                    Sha0 = "f96cea198ad1dd5617ac084a3d92c6107708c0ef",
                    Sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    Sha384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                    Sha512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
                },

                new HashTestCase
                {
                    Input = "a",
                    Sha0 = "37f297772fae4cb1ba39b6cf9cf0381180bd62f2",
                    Sha1 = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
                    Sha256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                    Sha384 = "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
                    Sha512 = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
                },

                new HashTestCase
                {
                    Input = "abc",
                    Sha0 = "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880",
                    Sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d",
                    Sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    Sha384 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                    Sha512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
                },

                new HashTestCase
                {
                    Input = "message digest",
                    Sha0 = "c1b0f222d150ebb9aa36a40cafdc8bcbed830b14",
                    Sha1 = "c12252ceda8be8994d5fa0290a47231c1d16aae3",
                    Sha256 = "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
                    Sha384 = "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
                    Sha512 = "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c"
                },

                new HashTestCase
                {
                    Input = "abcdefghijklmnopqrstuvwxyz",
                    Sha0 = "b40ce07a430cfd3c033039b9fe9afec95dc1bdcd",
                    Sha1 = "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
                    Sha256 = "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
                    Sha384 = "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
                    Sha512 = "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1"
                },

                new HashTestCase
                {
                    Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    Sha0 = "79e966f7a3a990df33e40e3d7f8f18d2caebadfa",
                    Sha1 = "761c457bf73b14d27e9e9265c46f4b4dda11f940",
                    Sha256 = "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
                    Sha384 = "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
                    Sha512 = "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894"
                },

                new HashTestCase
                {
                    Input = "For this sample, this 63-byte string will be used as input data",
                    Sha0 = "dda99bb3c3376907131166db9597040cd0f63ea5",
                    Sha1 = "4f0ea5cd0585a23d028abdc1a6684e5a8094dc49",
                    Sha256 = "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342",
                    Sha384 = "37b49ef3d08de53e9bd018b0630067bd43d09c427d06b05812f48531bce7d2a698ee2d1ed1ffed46fd4c3b9f38a8a557",
                    Sha512 = "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766"
                },

                new HashTestCase
                {
                    Input = "This is exactly 64 bytes long, not counting the terminating byte",
                    Sha0 = "922f7783393e8f2ee8b948c8dd7b6d542b19be4c",
                    Sha1 = "fb679f23e7d1ce053313e66e127ab1b444397057",
                    Sha256 = "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8",
                    Sha384 = "e28e35e25a1874908bf0958bb088b69f3d742a753c86993e9f4b1c4c21988f958bd1fe0315b195aca7b061213ac2a9bd",
                    Sha512 = "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a387d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030"
                },

                new HashTestCase
                {
                    Input = "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                    Sha0 = "a66bc4b1b05eb0a0c22625ea87e05363f1ca19d2",
                    Sha1 = "69e8e40e4a20b17a8de35505e2fe6ff1fe63cc96",
                    Sha256 = "e4326d0459653d7d3514674d713e74dc3df11ed4d30b4013fd327fdb9e394c26",
                    Sha384 = "1ca650f38480fa9dfb5729636bec4a935ebc1cd4c0055ee50cad2aa627e066871044fd8e6fdb80edf10b85df15ba7aab",
                    Sha512 = "d399507bbf5f2d0da51db1ff1fc51c1c9ff1de0937e00d01693b240e84fcc3400601429f45c297acc6e8fcf1e4e4abe9ff21a54a0d3d88888f298971bd206cd5"
                },

                new HashTestCase
                {
                    Input = "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                    Sha0 = "b1b8de4c612ea852c9e55ac6fdae3f7ee8bf56c0",
                    Sha1 = "7e9fb243f2cb25eab54b1217ab104d72ddec1c6a",
                    Sha256 = "0ab803344830f92089494fb635ad00d76164ad6e57012b237722df0d7ad26896",
                    Sha384 = "e3e3602f4d90c935321d788f722071a8809f4f09366f2825cd85da97ccd2955eb6b8245974402aa64789ed45293e94ba",
                    Sha512 = "97fb4ec472f3cb698b9c3c12a12768483e5b62bcdad934280750b4fa4701e5e0550a80bb0828342c19631ba55a55e1cee5de2fda91fc5d40e7bee1d4e6d415b3"
                },

                new HashTestCase
                {
                    Input = "Exactly 1000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX",
                    Sha0 = "98b59f2c2e9b87473f685d2339bbc839d84065ff",
                    Sha1 = "a26ab5cb975a0ebad8fde68cb157a05ad169b632",
                    Sha256 = "629730eb261524c260ac8135936f3593ed01d3ebc361ae265385ba44529935d9",
                    Sha384 = "530338f9e56c1c3c872df925468eae047f48fb8955d5da37b81e0879fff53927cbc64fb7f1b65316b203207c8a72b5bc",
                    Sha512 = "7635d618e14800a3c2c27b614c446baf09ea08ae64a087cd8218fc72b385d99d59a8940c7cacd67bafc0ef9e4da964e0626c5e3c30e83df7d9577198b61111d2"
                },

                new HashTestCase
                {
                    Input = "Exactly 4000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl",
                    Sha0 = "52412e546d2a96d55e619c3a80d436e4a2fd5482",
                    Sha1 = "e8b1acd9e623d51b9d4fbc84bd35e81bd2d617fa",
                    Sha256 = "f86ede611091b7762241505eb71ebb0bc614e022ceae2a78172cb93c4921d25d",
                    Sha384 = "6fd286c643d5c59b65d03633f44936e024bf65bfc39c92083467472eecc685f2f036b591226e6cb72b2569d5770f343b",
                    Sha512 = "09ce524502636f4e13dfe80f94192842682ed695d3c0745b3379fc67390ad87f30e551cdcdf5cfab2958442fb8f540e73f540cb1f778cbd88569ab75983f7bd6"
                },

                new HashTestCase
                {
                    Input = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                    Sha0 = "54a84ee72093c6265e264cdb0127a5b2334f19c8",
                    Sha1 = "3728b3fd827fe2bfd0900e0586a03ffd3394e647",
                    Sha256 = "4d25fccf8752ce470a58cd21d90939b7eb25f3fa418dd2da4c38288ea561e600",
                    Sha384 = "69cc75b95280bdd9e154e743903e37b1205aa382e92e051b1f48a6db9d0203f8a17c1762d46887037275606932d3381e",
                    Sha512 = "23450737795d2f6a13aa61adcca0df5eef6df8d8db2b42cd2ca8f783734217a73e9cabc3c9b8a8602f8aeaeb34562b6b1286846060f9809b90286b3555751f09"
                }
            };
        }

        internal record HashTestCase
        {
            public string Input { get; init; } = default!;

            public string Sha0 { get; init; } = default!;

            public string Sha1 { get; init; } = default!;

            public string Sha256 { get; init; } = default!;

            public string Sha384 { get; init; } = default!;

            public string Sha512 { get; init; } = default!;
        }
    }
}
