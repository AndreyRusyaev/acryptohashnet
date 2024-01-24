using System;
using System.Security.Cryptography;

namespace acryptohashnet
{
    public static class HashAlgorithmFactory
    {
        internal static HashAlgorithm Create(HashAlgorithms hashAlgorithm)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithms.Haval128:
                    return new Haval128();
                case HashAlgorithms.Haval160:
                    return new Haval160();
                case HashAlgorithms.Haval192:
                    return new Haval192();
                case HashAlgorithms.Haval224:
                    return new Haval224();
                case HashAlgorithms.Haval256:
                    return new Haval256();
                case HashAlgorithms.Md2:
                    return new MD2();
                case HashAlgorithms.Md4:
                    return new MD4();
                case HashAlgorithms.Md5:
                    return new MD5();
                case HashAlgorithms.RipeMd128:
                    return new RIPEMD128();
                case HashAlgorithms.RipeMd160:
                    return new RIPEMD160();
                case HashAlgorithms.Sha0:
                    return new SHA0();
                case HashAlgorithms.Sha1:
                    return new SHA1();
                case HashAlgorithms.Sha2_224:
                    return new Sha2_224();
                case HashAlgorithms.Sha2_256:
                    return new Sha2_256();
                case HashAlgorithms.Sha2_384:
                    return new Sha2_384();
                case HashAlgorithms.Sha2_512:
                    return new Sha2_512();
                case HashAlgorithms.Sha3_224:
                    return new Sha3_224();
                case HashAlgorithms.Sha3_256:
                    return new Sha3_256();
                case HashAlgorithms.Sha3_384:
                    return new Sha3_384();
                case HashAlgorithms.Sha3_512:
                    return new Sha3_512();
                case HashAlgorithms.Snefru128:
                    return new Snefru();
                case HashAlgorithms.Snefru256:
                    return new Snefru256();
                case HashAlgorithms.Tiger:
                    return new Tiger();
                case HashAlgorithms.Tiger2:
                    return new Tiger2();
                default:
                    throw new InvalidOperationException($"Unsupported value '{hashAlgorithm}'");
            }
        }
    }
}
