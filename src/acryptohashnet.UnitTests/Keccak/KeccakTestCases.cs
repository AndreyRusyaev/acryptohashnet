using System.Collections.Generic;

namespace acryptohashnet.UnitTests;

internal class KeccakTestCases
{
    public static IEnumerable<HashTestCase> All()
    {
        return new []
        {
            new HashTestCase
            {
                Message = "",
                Keccak224 = "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd",
                Keccak256 = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                Keccak384 = "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff",
                Keccak512 = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
            },

            new HashTestCase
            {
                Message = "a",
                Keccak224 = "7cf87d912ee7088d30ec23f8e7100d9319bff090618b439d3fe91308",
                Keccak256 = "3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb",
                Keccak384 = "85e964c0843a7ee32e6b5889d50e130e6485cffc826a30167d1dc2b3a0cc79cba303501a1eeaba39915f13baab5abacf",
                Keccak512 = "9c46dbec5d03f74352cc4a4da354b4e9796887eeb66ac292617692e765dbe400352559b16229f97b27614b51dbfbbb14613f2c10350435a8feaf53f73ba01c7c",
            },

            new HashTestCase
            {
                Message = "abc",
                Keccak224 = "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8",
                Keccak256 = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
                Keccak384 = "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e",
                Keccak512 = "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
            },

            new HashTestCase
            {
                Message = "message digest",
                Keccak224 = "b53b2cd638f440fa49916036acdb22245673992fb1b1963b96fb9e93",
                Keccak256 = "856ab8a3ad0f6168a4d0ba8d77487243f3655db6fc5b0e1669bc05b1287e0147",
                Keccak384 = "8a377db088c43e44040a2bfb26676704999d90527913cabff0a3484825daa54d3061e67da7d836a0805356962af310e8",
                Keccak512 = "cccc49fa63822b00004cf6c889b28a035440ffb3ef50e790599935518e2aefb0e2f1839170797f7763a5c43b2dcf02abf579950e36358d6d04dfddc2abac7545",
            },

            new HashTestCase
            {
                Message = "abcdefghijklmnopqrstuvwxyz",
                Keccak224 = "162bab64dc3ba594bd3b43fd8abec4aa03b36c2784cac53a58f9b076",
                Keccak256 = "9230175b13981da14d2f3334f321eb78fa0473133f6da3de896feb22fb258936",
                Keccak384 = "c5a708ec2178d8c398461547435e482cee0d85de3d75ddbff54e6606a7e9f994f023a6033b2bf4c516a5f71fc7470d1a",
                Keccak512 = "e55bdca64dfe33f36ae3153c727833f9947d92958073f4dd02e38a82d8acb282b1ee1330a68252a54c6d3d27306508ca765acd45606caeaf51d6bdc459f551f1",
            },

            new HashTestCase
            {
                Message = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                Keccak224 = "4fb72d7b6b24bd1f5d4b8ef559fd9188eb66caa01bce34c621a05412",
                Keccak256 = "6e61c013aef4c6765389ffcd406dd72e7e061991f4a3a8018190db86bd21ebb4",
                Keccak384 = "7377c5707506575c26937f3df0d44a773f8c7452c074ee1725c1ab62f741f95059459d64caebf35a7c247fe28616cab6",
                Keccak512 = "d5fa6b93d54a87bbde52dbb44daf96a3455daef9d60cdb922bc4b72a5bbba97c5bf8c59816fede302fc64e98ce1b864df7be671c968e43d1bae23ad76a3e702d",
            },

            new HashTestCase
            {
                Message = "For this sample, this 63-byte string will be used as input data",
                Keccak224 = "0cecbc1d624c0954cf4c886df36bbdc6e6ef0919149f814f4746b191",
                Keccak256 = "5f323aee7801af6f179257f97cde82b40c1b223bb0b05db960151ea29cf01e41",
                Keccak384 = "4f3ee67b695ba36b0943d4ec548937942d4293abdf28613012e18361822c01f69516aba578363b60aa38498a13e662bd",
                Keccak512 = "ee5e76ab9ea47c6abc82edee756a2a29d358b5efaa58ce93a9c06e824f9f068bda2309abed503f84d2ef8bb820bf72667e3b101d3af04f99824051da9cfeecaa",
            },

            new HashTestCase
            {
                Message = "This is exactly 64 bytes long, not counting the terminating byte",
                Keccak224 = "2218f58dd526bdba5b4cb3718e6520a0b32b005e0cd45314c95d0a84",
                Keccak256 = "2fd5854e44708f641c67704a46e5514fee6f49c7f413959244e6970ba611ca2e",
                Keccak384 = "d653a15939123d18d46ee69e8fc0581d96186f0f01e3d7d08f39aaaf5225ec2dcf0b3125cf1222f1595b90a2489be31a",
                Keccak512 = "93a3e13e692ed5eed7f7759c39e52f4c0b2c1e63d0a02b228ed32328d6555953c4753e093d54f08cf4d577fc35ad8ccd415107d12785bc7ddeb9b24896a00330",
            },

            new HashTestCase
            {
                Message = "By hashing data that is one byte less than a multiple of a hash block length (like this 127-byte string), bugs may be revealed.",
                Keccak224 = "c7d49eedd33c9e24fa40a4fab336273f104dc56b04f9265a7cd59e0b",
                Keccak256 = "90a7c4f2117a78357928ae7647e8d5861eb6d4f8c14ed44834233595102eb2e5",
                Keccak384 = "5592ac28933fe590942f888a5e3d6ed2ad43fabfe6c4b112e807df6c28c3a3bbd0d4f8c3e47a758acdd1b175953f26e7",
                Keccak512 = "5037c56e5d6ceaff522dd86b0005f60c5ef3521f85391a503cfec956e8ddbcb5f0b2c109fb3782beb464b1142ec48155076155bd3b278cb313eddd9de85ef16e",
            },

            new HashTestCase
            {
                Message = "And this textual data, astonishing as it may appear, is exactly 128 bytes in length, as are both SHA-384 and SHA-512 block sizes",
                Keccak224 = "bc33a3d851a416c1199181fbd1567405f79778472c1b356eb41f6573",
                Keccak256 = "74cfe2dcce964a3393f423bbd72d4633be72c835fcad70261af590aec355d844",
                Keccak384 = "7760facda4775ab048e805d7be1acc9bb2568d3065aad843cd779834af8c281dc4747d9a530758d06c19bccc582b11fd",
                Keccak512 = "1a1b6ca4bfe9598184c08ca5c69426962e0155e65de9534c2225cd4ea7953b496488539147d0095a65d097d6bc75da140f5573226b8fc50e009104fc217642e6",
            },

            new HashTestCase
            {
                Message = "Exactly 1000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX",
                Keccak224 = "010916de300df610f4b357a0c09daa2dc0511e67fcf72b69f26663d4",
                Keccak256 = "c8fe05f09258ea779f20bcd1054c36f53daa36bb6d3f1b6af5a17d9715b00447",
                Keccak384 = "ea766ed01c25f810224106c22abdf8a0569f5e223646be221d0a95570c20b5b86df98c36ee0b45179c2286c4a5d4acf2",
                Keccak512 = "f331d03b0f0ca62bb46eaca1dc67e8b2c309f8389675feef905836982822c2cfda11ea3aa087f492f8af43606756ef3a449d4420bb26ab20eaac01adca5cc845",
            },

            new HashTestCase
            {
                Message = "Exactly 4000 bytes: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijkl",
                Keccak224 = "ca7ad59b03af34a1a6d453041c7538b379df01646a7f146c6bd4164a",
                Keccak256 = "7bcf4e06d4c379e58ef144af5058bf5e5516dcbf5bdf1559a215a6b69e3db5a0",
                Keccak384 = "5ac89925b23daa2fc143a574ba3463a5239707646a78c557c235268cf227731d3d7ce1a90fadda5c15b3746815d5eb04",
                Keccak512 = "f523a64f3e27b3097672b719a939efc84b0d7c3232d983aec47baac1bf8e7857971f4d9c986c10196a4319a76b0adb7a0921eb6767ade31088b320693a68c65a",
            },

            new HashTestCase
            {
                Message = "Four score and seven years ago our fathers brought forth on this continent, a new nation, conceived in Liberty, and dedicated to the proposition that all men are created equal.  Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived and so dedicated, can long endure. We are met on a great battlefield of that war.  We have come to dedicate a portion of that field, as a final resting place for those who here gave their lives that that nation might live.  It is altogether fitting and proper that we should do this.  But, in a larger sense, we can not dedicate--we can not consecrate--we can not hallow--this ground.  The brave men, living and dead, who struggled here, have consecrated it, far above our poor power to add or detract.  The world will little note, nor long remember what we say here, but it can never forget what they did here.  It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced.  It is rather for us to be here dedicated to the great task remaining before us--that from these honored dead we take increased devotion to that cause for which they gave the last full measure of devotion--that we here highly resolve that these dead shall not have died in vain--that this nation, under God, shall have a new birth of freedom--and that government of the people, by the people, for the people, shall not perish from the earth.  -- President Abraham Lincoln, November 19, 1863",
                Keccak224 = "c2a98ea5b07fdcc9a233be45553d637ae5b55420a167a9ca04039516",
                Keccak256 = "5db776eea0759f45aaacd10a1c78cbf1ed5f08e1f46514ced4e5563a714b4963",
                Keccak384 = "4e33882e95c1120fb3c5e020c1d848f63d7f507f7c12d5935611dfc3c7e0e4290034c9383223038ab5cf5d154f016cfb",
                Keccak512 = "9046e52f998fd1635e1c0f9f9b484373d4b5c76015cce749610c53482f839096662ff2a6b137beacc46d1cff7da08d59cb9e030357a4a83d9e1851879057dc67",
            },

            new HashTestCase
            {
                Message = new string('A', 56),
                Keccak224 = "18a5c785825139a07a7cd9a0c4b9f83137c394f4bf7f814d466151cb",
                Keccak256 = "3c8a6a0f6b529162f6c494af5097750d4ad67d03ffbe400efc0aa40ca33c799d",
                Keccak384 = "34d8aa7f8d544b6e928cfb3179c59140a5274fef3e2c6e21164c314b5a5a77a5b435bec7759a41af03bb96b3fd33b61f",
                Keccak512 = "e1f0e6da6dfab95a0391accffda90dcafe00fc3072c518cf9b0b3f3ba9f7eaea18797e4479daa8e6d763cffa30351090fcb4f7ccb3b472d5367484d1766beeac",
            },

            new HashTestCase
            {
                Message = new string('A', 112),
                Keccak224 = "e66d397f37f249cef4797a0df3b836d17a826c60fe99fe897779caea",
                Keccak256 = "ea652ab7a6215a341cc83c80388e9c383225d825bf6ef8e6a30c4c0a69f00598",
                Keccak384 = "f5370e3fc6470242988e3af337191283f6ea4ae872346f07d595c183972667b296410dc679ac0332dedb15eee29a5596",
                Keccak512 = "8b9173b5a0f443f655cb557b48d690e2159d35583bfc93b6deb89175dccbd39da0754dca75f6a241d05aa551ee26fde3780554e944ae974043e127630bb0f623",
            }
        };
    }

    internal record HashTestCase
    {
        public string Message { get; init; } = default!;

        public string Keccak224 { get; init; } = default!;

        public string Keccak256 { get; init; } = default!;

        public string Keccak384 { get; init; } = default!;

        public string Keccak512 { get; init; } = default!;
    }
}
