using System.Collections.Generic;

namespace acryptohashnet.UnitTests
{
    internal static class HavalTestCases
    {
        public static IEnumerable<HashTestCase> All()
        {
            return new[]
            {
                new HashTestCase
                {
                    Input = "",
                    Haval128Pass3 = "c68f39913f901f3ddf44c707357a7d70",
                    Haval128Pass4 = "ee6bbf4d6a46a679b3a856c88538bb98",
                    Haval128Pass5 = "184b8482a0c050dca54b59c7f05bf5dd",
                    Haval160Pass3 = "d353c3ae22a25401d257643836d7231a9a95f953",
                    Haval160Pass4 = "1d33aae1be4146dbaaca0b6e70d7a11f10801525",
                    Haval160Pass5 = "255158cfc1eed1a7be7c55ddd64d9790415b933b",
                    Haval192Pass3 = "e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e",
                    Haval192Pass4 = "4a8372945afa55c7dead800311272523ca19d42ea47b72da",
                    Haval192Pass5 = "4839d0626f95935e17ee2fc4509387bbe2cc46cb382ffe85",
                    Haval224Pass3 = "c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d",
                    Haval224Pass4 = "3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e",
                    Haval224Pass5 = "4a0513c032754f5582a758d35917ac9adf3854219b39e3ac77d1837e",
                    Haval256Pass3 = "4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",
                    Haval256Pass4 = "c92b2e23091e80e375dadce26982482d197b1a2521be82da819f8ca2c579b99b",
                    Haval256Pass5 = "be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330",
                },

                new HashTestCase
                {
                    Input = "a",
                    Haval128Pass3 = "0cd40739683e15f01ca5dbceef4059f1",
                    Haval128Pass4 = "5cd07f03330c3b5020b29ba75911e17d",
                    Haval128Pass5 = "f23fbe704be8494bfa7a7fb4f8ab09e5",
                    Haval160Pass3 = "4da08f514a7275dbc4cece4a347385983983a830",
                    Haval160Pass4 = "e0a5be29627332034d4dd8a910a1a0e6fe04084d",
                    Haval160Pass5 = "f5147df7abc5e3c81b031268927c2b5761b5a2b5",
                    Haval192Pass3 = "b359c8835647f5697472431c142731ff6e2cddcacc4f6e08",
                    Haval192Pass4 = "856c19f86214ea9a8a2f0c4b758b973cce72a2d8ff55505c",
                    Haval192Pass5 = "5ffa3b3548a6e2cfc06b7908ceb5263595df67cf9c4b9341",
                    Haval224Pass3 = "731814ba5605c59b673e4caae4ad28eeb515b3abc2b198336794e17b",
                    Haval224Pass4 = "742f1dbeeaf17f74960558b44f08aa98bdc7d967e6c0ab8f799b3ac1",
                    Haval224Pass5 = "67b3cb8d4068e3641fa4f156e03b52978b421947328bfb9168c7655d",
                    Haval256Pass3 = "47c838fbb4081d9525a0ff9b1e2c05a98f625714e72db289010374e27db021d8",
                    Haval256Pass4 = "e686d2394a49b44d306ece295cf9021553221db132b36cc0ff5b593d39295899",
                    Haval256Pass5 = "de8fd5ee72a5e4265af0a756f4e1a1f65c9b2b2f47cf17ecf0d1b88679a3e22f",
                },

                new HashTestCase
                {
                    Input = "HAVAL",
                    Haval128Pass3 = "dc1f3c893d17cc4edd9ae94af76a0af0",
                    Haval128Pass4 = "958195d3dac591030eaa0292a37a0cf2",
                    Haval128Pass5 = "c97990f4fcc8fba76af935c405995355",
                    Haval160Pass3 = "8822bc6f3e694e73798920c77ce3245120dd8214",
                    Haval160Pass4 = "221ba4dd206172f12c2eba3295fde08d25b2f982",
                    Haval160Pass5 = "7730ca184cea2272e88571a7d533e035f33b1096",
                    Haval192Pass3 = "8da26ddab4317b392b22b638998fe65b0fbe4610d345cf89",
                    Haval192Pass4 = "0c1396d7772689c46773f3daaca4efa982adbfb2f1467eea",
                    Haval192Pass5 = "794a896d1780b76e2767cc4011bad8885d5ce6bd835a71b8",
                    Haval224Pass3 = "ad33e0596c575d7175e9f72361ca767c89e46e2609d88e719ee69aaa",
                    Haval224Pass4 = "85538ffc06f3b1c693c792c49175639666f1dde227da8bd000c1e6b4",
                    Haval224Pass5 = "9d7ae77b8c5c8c1c0ba854ebe3b2673c4163cfd304ad7cd527ce0c82",
                    Haval256Pass3 = "91850c6487c9829e791fc5b58e98e372f3063256bb7d313a93f1f83b426aedcc",
                    Haval256Pass4 = "e20643cfa66f5be2145d13ed09c2ff622b3f0da426a693fa3b3e529ca89e0d3c",
                    Haval256Pass5 = "153d2c81cd3c24249ab7cd476934287af845af37f53f51f5c7e2be99ba28443f",
                },

                new HashTestCase
                {
                    Input = "0123456789",
                    Haval128Pass3 = "d4be2164ef387d9f4d46ea8efb180cf5",
                    Haval128Pass4 = "2215d3702a80025c858062c53d76cbe5",
                    Haval128Pass5 = "466fdcd81c3477cac6a31ffa1c999ca8",
                    Haval160Pass3 = "be68981eb3ebd3f6748b081ee5d4e1818f9ba86c",
                    Haval160Pass4 = "e387c743d14df304ce5c7a552f4c19ca9b8e741c",
                    Haval160Pass5 = "41cc7c1267e88cef0bb93697d0b6c8afe59061e6",
                    Haval192Pass3 = "de561f6d818a760d65bdd2823abe79cdd97e6cfa4021b0c8",
                    Haval192Pass4 = "c3a5420bb9d7d82a168f6624e954aaa9cdc69fb0f67d785e",
                    Haval192Pass5 = "a0b635746e6cffffd4b4a503620fef1040c6c0c5c326476e",
                    Haval224Pass3 = "ee345c97a58190bf0f38bf7ce890231aa5fcf9862bf8e7bebbf76789",
                    Haval224Pass4 = "bebd7816f09baeecf8903b1b9bc672d9fa428e462ba699f814841529",
                    Haval224Pass5 = "59836d19269135bc815f37b2aeb15f894b5435f2c698d57716760f2b",
                    Haval256Pass3 = "63238d99c02be18c3c5db7cce8432f51329012c228ccc17ef048a5d0fd22d4ae",
                    Haval256Pass4 = "ace5d6e5b155f7c9159f6280327b07cbd4ff54143dc333f0582e9bceb895c05d",
                    Haval256Pass5 = "357e2032774abbf5f04d5f1dec665112ea03b23e6e00425d0df75ea155813126",
                },

                new HashTestCase
                {
                    Input = "abcdefghijklmnopqrstuvwxyz",
                    Haval128Pass3 = "dc502247fb3eb8376109eda32d361d82",
                    Haval128Pass4 = "b2a73b99775ffb17cd8781b85ec66221",
                    Haval128Pass5 = "0efff71d7d14344cba1f4b25f924a693",
                    Haval160Pass3 = "eba9fa6050f24c07c29d1834a60900ea4e32e61b",
                    Haval160Pass4 = "1c7884af86d11ac120fe5df75cee792d2dfa48ef",
                    Haval160Pass5 = "917836a9d27eed42d406f6002e7d11a0f87c404c",
                    Haval192Pass3 = "a25e1456e6863e7d7c74017bb3e098e086ad4be0580d7056",
                    Haval192Pass4 = "2e2e581d725e799fda1948c75e85a28cfe1cf0c6324a1ada",
                    Haval192Pass5 = "85f1f1c0eca04330cf2de5c8c83cf85a611b696f793284de",
                    Haval224Pass3 = "06ae38ebc43db58bd6b1d477c7b4e01b85a1e7b19b0bd088e33b58d1",
                    Haval224Pass4 = "a0ac696cdb2030fa67f6cc1d14613b1962a7b69b4378a9a1b9738796",
                    Haval224Pass5 = "1b360acff7806502b5d40c71d237cc0c40343d2000ae2f65cf487c94",
                    Haval256Pass3 = "72fad4bde1da8c8332fb60561a780e7f504f21547b98686824fc33fc796afa76",
                    Haval256Pass4 = "124f6eb645dc407637f8f719cc31250089c89903bf1db8fac21ea4614df4e99a",
                    Haval256Pass5 = "c9c7d8afa159fd9e965cb83ff5ee6f58aeda352c0eff005548153a61551c38ee",
                },

                new HashTestCase
                {
                    Input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
                    Haval128Pass3 = "de5eb3f7d9eb08fae7a07d68e3047ec6",
                    Haval128Pass4 = "cad57c0563bda208d66bb89eb922e2a2",
                    Haval128Pass5 = "4b27d04ddb516bdcdfeb96eb8c7c8e90",
                    Haval160Pass3 = "97dc988d97caae757be7523c4e8d4ea63007a4b9",
                    Haval160Pass4 = "148334aad24b658bdc946c521cdd2b1256608c7b",
                    Haval160Pass5 = "6ddbde98ea1c4f8c7f360fb9163c7c952680aa70",
                    Haval192Pass3 = "def6653091e3005b43a61681014a066cd189009d00856ee7",
                    Haval192Pass4 = "e5c9f81ae0b31fc8780fc37cb63bb4ec96496f79a9b58344",
                    Haval192Pass5 = "d651c8ac45c9050810d9fd64fc919909900c4664be0336d0",
                    Haval224Pass3 = "939f7ed7801c1ce4b32bc74a4056eee6081c999ed246907adba880a7",
                    Haval224Pass4 = "3e63c95727e0cd85d42034191314401e42ab9063a94772647e3e8e0f",
                    Haval224Pass5 = "180aed7f988266016719f60148ba2c9b4f5ec3b9758960fc735df274",
                    Haval256Pass3 = "899397d96489281e9e76d5e65abab751f312e06c06c07c9c1d42abd31bb6a404",
                    Haval256Pass4 = "46a3a1dfe867ede652425ccd7fe8006537ead26372251686bea286da152dc35a",
                    Haval256Pass5 = "b45cb6e62f2b1320e4f8f1b0b273d45add47c321fd23999dcf403ac37636d963",
                },

                new HashTestCase
                {
                    Input = "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89452821E638D01377BE5466CF34E90C6CC0AC29B7C97C50DD3F84D5B5B54709179216D5D98979FB1BD1310BA698DFB5AC2FFD72DBD01ADFB7B8E1AFED6A267E96BA7C9045F12C7F9924A19947B3916CF70801F2E2858EFC16636920D871574E69A458FEA3F4933D7E0D95748F728EB658718BCD5882154AEE7B54A41DC25A59B5",
                    Haval128Pass3 = "7a4272c08c8439de627fd5f5fee6ca16",
                    Haval128Pass4 = "b163a0236635f8b2ffcf6e10c3ce2bb2",
                    Haval128Pass5 = "e8271bfc50905f510b06690808abdb2b",
                    Haval160Pass3 = "3fadf42851f001aae23cc966611625a83bda8a29",
                    Haval160Pass4 = "eac16e54b3a8881169e6a928c2e2e5e042df8305",
                    Haval160Pass5 = "494a002c5c2a4fd406097a55c078e0d1ef6815ce",
                    Haval192Pass3 = "95bc146c17e355de03842c22d9fe3821fe7aaa9834f09c63",
                    Haval192Pass4 = "d1f8b6e0f8e939f21013b9bca5b25d8067974aa254ec71cf",
                    Haval192Pass5 = "02e968be4b6ee32ec67bcca3ab53d8be706e8ceb36718bca",
                    Haval224Pass3 = "3efaf428ccded50600039a5196c3e6ec88cf06bc5e55cb602cabfdac",
                    Haval224Pass4 = "0f0120310e2dd9972e2e1619a96cc20478271d090b6c21e7eb33eb0c",
                    Haval224Pass5 = "36a5bcf298afe7f6796284b29c591896d54b4e982ed2c847c9857ccf",
                    Haval256Pass3 = "f92f518fe5b1e7e7d76e295dc3d0a9301da56e29374597eb6ff5a1f8c4fb9f93",
                    Haval256Pass4 = "68ffd0fbc2e2973b4baae73a418029fec08c050b4cf9352c29411510f730cd08",
                    Haval256Pass5 = "24658c4ad929b90693014330089dbeedbf1c28141379b8efb83a8f74f9e91c1f",
                }
            };
        }

        internal record HashTestCase
        {
            public string Input { get; init; } = default!;

            public string Haval128Pass3 { get; init; } = default!;

            public string Haval128Pass4 { get; init; } = default!;

            public string Haval128Pass5 { get; init; } = default!;

            public string Haval160Pass3 { get; init; } = default!;

            public string Haval160Pass4 { get; init; } = default!;

            public string Haval160Pass5 { get; init; } = default!;

            public string Haval192Pass3 { get; init; } = default!;

            public string Haval192Pass4 { get; init; } = default!;

            public string Haval192Pass5 { get; init; } = default!;

            public string Haval224Pass3 { get; init; } = default!;

            public string Haval224Pass4 { get; init; } = default!;

            public string Haval224Pass5 { get; init; } = default!;

            public string Haval256Pass3 { get; init; } = default!;

            public string Haval256Pass4 { get; init; } = default!;

            public string Haval256Pass5 { get; init; } = default!;
        }
    }
}
