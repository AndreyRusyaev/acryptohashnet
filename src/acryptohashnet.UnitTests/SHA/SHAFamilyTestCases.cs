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
                    Message = "",
                    Md2 = "8350e5a3e24c153df2275c9f80692773",
                    Md4 = "31d6cfe0d16ae931b73c59d7e0c089c0",
                    Md5 = "d41d8cd98f00b204e9800998ecf8427e",
                    Sha0 = "f96cea198ad1dd5617ac084a3d92c6107708c0ef",
                    Sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    Sha2_224 = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
                    Sha2_256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    Sha2_384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
                    Sha2_512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                    Sha3_224 = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
                    Sha3_256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
                    Sha3_384 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
                    Sha3_512 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
                },

                new HashTestCase
                {
                    Message = "a",
                    Md2 = "32ec01ec4a6dac72c0ab96fb34c0b5d1",
                    Md4 = "bde52cb31de33e46245e05fbdbd6fb24",
                    Md5 = "0cc175b9c0f1b6a831c399e269772661",
                    Sha0 = "37f297772fae4cb1ba39b6cf9cf0381180bd62f2",
                    Sha1 = "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
                    Sha2_224 = "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
                    Sha2_256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
                    Sha2_384 = "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
                    Sha2_512 = "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75",
                    Sha3_224 = "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b",
                    Sha3_256 = "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
                    Sha3_384 = "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9",
                    Sha3_512 = "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a"
                },

                new HashTestCase
                {
                    Message = "abc",
                    Md2 = "da853b0d3f88d99b30283a69e6ded6bb",
                    Md4 = "a448017aaf21d8525fc10ae87aa6729d",
                    Md5 = "900150983cd24fb0d6963f7d28e17f72",
                    Sha0 = "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880",
                    Sha1 = "a9993e364706816aba3e25717850c26c9cd0d89d",
                    Sha2_224 = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
                    Sha2_256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                    Sha2_384 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
                    Sha2_512 = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                    Sha3_224 = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
                    Sha3_256 = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                    Sha3_384 = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
                    Sha3_512 = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
                },

                new HashTestCase
                {
                    Message = "message digest",
                    Md2 = "ab4f496bfb2a530b219ff33031fe06b0",
                    Md4 = "d9130a8164549fe818874806e1c7014b",
                    Md5 = "f96b697d7cb7938d525a2f31aaf161d0",
                    Sha0 = "c1b0f222d150ebb9aa36a40cafdc8bcbed830b14",
                    Sha1 = "c12252ceda8be8994d5fa0290a47231c1d16aae3",
                    Sha2_224 = "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
                    Sha2_256 = "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
                    Sha2_384 = "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
                    Sha2_512 = "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038ddb372a89826046de66687bb420e7c",
                    Sha3_224 = "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8",
                    Sha3_256 = "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd",
                    Sha3_384 = "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5",
                    Sha3_512 = "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59"
                },

                new HashTestCase
                {
                    Message = "abcdefghijklmnopqrstuvwxyz",
                    Md2 = "4e8ddff3650292ab5a4108c3aa47940b",
                    Md4 = "d79e1c308aa5bbcdeea8ed63df412da9",
                    Md5 = "c3fcd3d76192e4007dfb496cca67e13b",
                    Sha0 = "b40ce07a430cfd3c033039b9fe9afec95dc1bdcd",
                    Sha1 = "32d10c7b8cf96570ca04ce37f2a19d84240d3a89",
                    Sha2_224 = "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
                    Sha2_256 = "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
                    Sha2_384 = "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
                    Sha2_512 = "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5441fb0f321389f77f48a879c7b1f1",
                    Sha3_224 = "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239",
                    Sha3_256 = "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521",
                    Sha3_384 = "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f",
                    Sha3_512 = "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68"
                },

                new HashTestCase
                {
                    Message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    Md2 = "da33def2a42df13975352846c30338cd",
                    Md4 = "043f8582f241db351ce627e153e7f0e4",
                    Md5 = "d174ab98d277d9f5a5611c2c9f419d9f",
                    Sha0 = "79e966f7a3a990df33e40e3d7f8f18d2caebadfa",
                    Sha1 = "761c457bf73b14d27e9e9265c46f4b4dda11f940",
                    Sha2_224 = "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
                    Sha2_256 = "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
                    Sha2_384 = "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
                    Sha2_512 = "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
                    Sha3_224 = "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e",
                    Sha3_256 = "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f",
                    Sha3_384 = "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291",
                    Sha3_512 = "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163"
                },

                new HashTestCase
                {
                    Message = "For this sample, this 63-byte string will be used as input data",
                    Md2 = "4d2b317fb976ad61b23eaf8fe8592bcf",
                    Md4 = "0b501fa8881a5caa0d83fe7a3d2d186d",
                    Md5 = "b02752d13a05fa8d7d04aabd158ff9d1",
                    Sha0 = "dda99bb3c3376907131166db9597040cd0f63ea5",
                    Sha1 = "4f0ea5cd0585a23d028abdc1a6684e5a8094dc49",
                    Sha2_224 = "0873433e1c8749dad0e34f92aff11c4b2ca310356283817747aa6940",
                    Sha2_256 = "f08a78cbbaee082b052ae0708f32fa1e50c5c421aa772ba5dbb406a2ea6be342",
                    Sha2_384 = "37b49ef3d08de53e9bd018b0630067bd43d09c427d06b05812f48531bce7d2a698ee2d1ed1ffed46fd4c3b9f38a8a557",
                    Sha2_512 = "b3de4afbc516d2478fe9b518d063bda6c8dd65fc38402dd81d1eb7364e72fb6e6663cf6d2771c8f5a6da09601712fb3d2a36c6ffea3e28b0818b05b0a8660766",
                    Sha3_224 = "24ca73a54f94fb66634e7a975e0ccdf9411446a6e6125564dc409085",
                    Sha3_256 = "66c3646740ff4c95eb5db97cfae97f954340f54dc22e0f1eb169b7ce0f611881",
                    Sha3_384 = "ea135c8672638075a3f7e772b4b5620f60168e95d7e8b4f8e37740f96753fac8f9f929d25356b7dc59f0c8c53f58701b",
                    Sha3_512 = "4d26f437b17e35b2c8c352c813b3fc387cd69b6f9bf3dcfdba281ad35e76c8b731f6394e1c9694984eeb4d8bd6e368989162928c1f9d9ab7a3f3681102c944fd"
                },

                new HashTestCase
                {
                    Message = "This is exactly 64 bytes long, not counting the terminating byte",
                    Md2 = "6caa9cd8554a2152f201f9705d7027a6",
                    Md4 = "572c146781d8abc6d5f827844cf4d94b",
                    Md5 = "debcb70bf9c8e83659ef1d85aa51c5e9",
                    Sha0 = "922f7783393e8f2ee8b948c8dd7b6d542b19be4c",
                    Sha1 = "fb679f23e7d1ce053313e66e127ab1b444397057",
                    Sha2_224 = "d92622d56f83d869a884f6cc0763e90c4520a21e1cc429841e4584d2",
                    Sha2_256 = "ab64eff7e88e2e46165e29f2bce41826bd4c7b3552f6b382a9e7d3af47c245f8",
                    Sha2_384 = "e28e35e25a1874908bf0958bb088b69f3d742a753c86993e9f4b1c4c21988f958bd1fe0315b195aca7b061213ac2a9bd",
                    Sha2_512 = "70aefeaa0e7ac4f8fe17532d7185a289bee3b428d950c14fa8b713ca09814a387d245870e007a80ad97c369d193e41701aa07f3221d15f0e65a1ff970cedf030",
                    Sha3_224 = "7590bf3e5bb176529c30679448bfe63bb489ca27b44e5e30784a85e1",
                    Sha3_256 = "d7fcb87d155ffdeb4a9f154a6b241631038cad064e3d4cffc46900fbfb557d4d",
                    Sha3_384 = "2cc2687e269bded5e3fc2cf0b4170b625a011535e0cef7e6ef3f5b3f26490f4caad6fe72b1705a30c8c2572dfdf1b968",
                    Sha3_512 = "cfb955003293d477b2189e8a6f3f9cee83906b5bcca3db59c2853ad0e85350c52636685d99aa01c55e34412a6ef40ab6fc16119f45509c73e9e1e47cd7da2090"
                },

                new HashTestCase
                {
                    Message = "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                    Md2 = "303a4941ba2a3fb01430289503d074ee",
                    Md4 = "0c1d5450ebdf236aceee8b0b66cdfa72",
                    Md5 = "50c757c2522680444582b8f4572b32f2",
                    Sha0 = "a66bc4b1b05eb0a0c22625ea87e05363f1ca19d2",
                    Sha1 = "69e8e40e4a20b17a8de35505e2fe6ff1fe63cc96",
                    Sha2_224 = "49e54148d21d457f2ffe28532543d91da98724c9883e67682301dec4",
                    Sha2_256 = "e4326d0459653d7d3514674d713e74dc3df11ed4d30b4013fd327fdb9e394c26",
                    Sha2_384 = "1ca650f38480fa9dfb5729636bec4a935ebc1cd4c0055ee50cad2aa627e066871044fd8e6fdb80edf10b85df15ba7aab",
                    Sha2_512 = "d399507bbf5f2d0da51db1ff1fc51c1c9ff1de0937e00d01693b240e84fcc3400601429f45c297acc6e8fcf1e4e4abe9ff21a54a0d3d88888f298971bd206cd5",
                    Sha3_224 = "d1e3c1f63938eed5a5f0f950882a0e4815005f092955360fd95df961",
                    Sha3_256 = "c790addecbb54333aa90e6325d7173069982aee4763fd1d85f5816501b741058",
                    Sha3_384 = "bf28930432e04820a983171bf03567c291eee90a4a4d44ede97718c59bdd219ea541031cdfba4d7a4b047a862a406fde",
                    Sha3_512 = "be7f09cef9492217dd3e822d0221cb94c91941a187d75171907a80ae4d0e3d925126596a8da3111d7937c97eba794c9be22eb8ef1d5be9e647c29259119a1148"
                },

                new HashTestCase
                {
                    Message = "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                    Md2 = "0b4e8940897149509fd7bc5078032578",
                    Md4 = "dadc76e37d7b36b2e313a13657ac5f9f",
                    Md5 = "268dc47e6b6f19a86481374b2ced6f18",
                    Sha0 = "b1b8de4c612ea852c9e55ac6fdae3f7ee8bf56c0",
                    Sha1 = "7e9fb243f2cb25eab54b1217ab104d72ddec1c6a",
                    Sha2_224 = "5a69ccca0b5e7f84efda7c026d010fa46569c03f97b4440eba32b941",
                    Sha2_256 = "0ab803344830f92089494fb635ad00d76164ad6e57012b237722df0d7ad26896",
                    Sha2_384 = "e3e3602f4d90c935321d788f722071a8809f4f09366f2825cd85da97ccd2955eb6b8245974402aa64789ed45293e94ba",
                    Sha2_512 = "97fb4ec472f3cb698b9c3c12a12768483e5b62bcdad934280750b4fa4701e5e0550a80bb0828342c19631ba55a55e1cee5de2fda91fc5d40e7bee1d4e6d415b3",
                    Sha3_224 = "d2f7704e038f5be195c3fd2e7de433749e585ebb0b29cf18d479b8b3",
                    Sha3_256 = "f420ebf4fcd128355fe703154acb085c6178bc8d415adf3b29485ba21e133d37",
                    Sha3_384 = "4dce6c4657b749c680e95e98f83bd60162ed07713dc8a39bd6cb72efb72bb58831006dc3bc16d6e9000825d3417b8e56",
                    Sha3_512 = "758c72814a27e32aabfdf49d421a67a2281cdcc0d9f5ac77482161f5b042bd6f3d251065373647d59f393ac3818760784db6cf9ae263a3bd3e167fe9a6e8a503"
                },

                new HashTestCase
                {
                    Message = "Exactly 1000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX",
                    Md2 = "cbede9d6080aea700605ad4565a9e3af",
                    Md4 = "0fc4c9f881efddbd5712c8a52d4f5271",
                    Md5 = "8552d46f34d75f4f770ea10227d73cb9",
                    Sha0 = "98b59f2c2e9b87473f685d2339bbc839d84065ff",
                    Sha1 = "a26ab5cb975a0ebad8fde68cb157a05ad169b632",
                    Sha2_224 = "9ca47d8b16589c19fe4f40545ecc0c6b106bf9e8f30f914136e11d30",
                    Sha2_256 = "629730eb261524c260ac8135936f3593ed01d3ebc361ae265385ba44529935d9",
                    Sha2_384 = "530338f9e56c1c3c872df925468eae047f48fb8955d5da37b81e0879fff53927cbc64fb7f1b65316b203207c8a72b5bc",
                    Sha2_512 = "7635d618e14800a3c2c27b614c446baf09ea08ae64a087cd8218fc72b385d99d59a8940c7cacd67bafc0ef9e4da964e0626c5e3c30e83df7d9577198b61111d2",
                    Sha3_224 = "b5b7b2369667f84128c345ce1e6c275e5a1ab13a5b3f6e3ee3518c8a",
                    Sha3_256 = "182a8bf1ec6e1f733b021fdce87be2b95b1b092673c0513f3219e1fb4a78210c",
                    Sha3_384 = "bd70cb9ffd007619e812e6fe58a2936f9feb9c437ccd18c41985c10c3b19ba70c6b4b0a1ed6f5fe029bebfa2d8bcfc0d",
                    Sha3_512 = "ae3a6eecb8b93e93e7406a4758717b2745575be72a7f5ce5ca66d6816d2cbea7bb3cb41d6746a1a6aef2887aa8ffa1d2bf68b11ccd4645d23dfd55c53683e567"
                },

                new HashTestCase
                {
                    Message = "Exactly 4000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl",
                    Md2 = "518453006c8c5a4f389d722322186099",
                    Md4 = "a273308cf00e3b57839733972abeefd3",
                    Md5 = "2f5d1fb0a5a7281d92333b1012719965",
                    Sha0 = "52412e546d2a96d55e619c3a80d436e4a2fd5482",
                    Sha1 = "e8b1acd9e623d51b9d4fbc84bd35e81bd2d617fa",
                    Sha2_224 = "71472f8c256039f6387368edfcd5d252d67424619b6591a91bf57431",
                    Sha2_256 = "f86ede611091b7762241505eb71ebb0bc614e022ceae2a78172cb93c4921d25d",
                    Sha2_384 = "6fd286c643d5c59b65d03633f44936e024bf65bfc39c92083467472eecc685f2f036b591226e6cb72b2569d5770f343b",
                    Sha2_512 = "09ce524502636f4e13dfe80f94192842682ed695d3c0745b3379fc67390ad87f30e551cdcdf5cfab2958442fb8f540e73f540cb1f778cbd88569ab75983f7bd6",
                    Sha3_224 = "5fd5544120471c3b9835be4c0ae8907013519037b3610829d8c52e46",
                    Sha3_256 = "9a009840759539dacecaa8d2663ecedc2ce32f0a6e3799131d5a04fcb390814e",
                    Sha3_384 = "074b44ee6e3bd3ec395a7dfc312685d697db43c74dde92ff746487e10846eae10081281074230f9606c0adb6337223bd",
                    Sha3_512 = "088af132aebab984dc4d0c978faff16a987cedd52f0059ba9a87c9c92cfbac41b6d7c5cee0c91e16d800a65d55bbc2a8d6ba52ad1a166e31e905aaf0a040e7dc"
                },

                new HashTestCase
                {
                    Message = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                    Md2 = "58bacf68f1f8ed5a3515ae0607b3b511",
                    Md4 = "50385e2a1f0b9869040a289eff3abff2",
                    Md5 = "43696c3abe0610e776cde9bf4c052421",
                    Sha0 = "54a84ee72093c6265e264cdb0127a5b2334f19c8",
                    Sha1 = "3728b3fd827fe2bfd0900e0586a03ffd3394e647",
                    Sha2_224 = "62a41ab0961bcdd22db70b896db3955c1d04096af6de47f5aaad1226",
                    Sha2_256 = "4d25fccf8752ce470a58cd21d90939b7eb25f3fa418dd2da4c38288ea561e600",
                    Sha2_384 = "69cc75b95280bdd9e154e743903e37b1205aa382e92e051b1f48a6db9d0203f8a17c1762d46887037275606932d3381e",
                    Sha2_512 = "23450737795d2f6a13aa61adcca0df5eef6df8d8db2b42cd2ca8f783734217a73e9cabc3c9b8a8602f8aeaeb34562b6b1286846060f9809b90286b3555751f09",
                    Sha3_224 = "6ac187368fc334e8c774c89f7e5f34eda94e921e2ac021a48dae9fca",
                    Sha3_256 = "9b50251ac0a8cbadc9aaf2596932443cc2f33f11d79c3ef2a67dd7c867c0e71b",
                    Sha3_384 = "6ca40c91ca4f4ba8bc530cc7dcd69d9bcc891fa58692a0e0700f4a7e3945d8c9940f1071d2f8b4ad47c5c8cb9f304e1d",
                    Sha3_512 = "d889af1035efe42795a971a2d4da562574b0e00353179086a0d8d21fa65517def799a19f2d4d9dbd810cb7969fe73fe4ab8597fef7d04e98b3ab64b3bee4237c"
                }
            };
        }

        internal record HashTestCase
        {
            public string Message { get; init; } = default!;

            public string Md2 { get; init; } = default!;

            public string Md4 { get; init; } = default!;

            public string Md5 { get; init; } = default!;

            public string Sha0 { get; init; } = default!;

            public string Sha1 { get; init; } = default!;

            public string Sha2_224 { get; init; } = default!;

            public string Sha2_256 { get; init; } = default!;

            public string Sha2_384 { get; init; } = default!;

            public string Sha2_512 { get; init; } = default!;

            public string Sha3_224 { get; init; } = default!;

            public string Sha3_256 { get; init; } = default!;

            public string Sha3_384 { get; init; } = default!;

            public string Sha3_512 { get; init; } = default!;
        }
    }
}
