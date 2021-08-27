
namespace Home.Andir.Cryptography
{
    public sealed class Haval128 : HavalBase
    {
        public Haval128()
            : base(HavalHashSize.HashSize128, HavalPassCount.Pass5)
        { }

        public Haval128(HavalPassCount havalPassCount)
            : base(HavalHashSize.HashSize128, havalPassCount)
        { }
    }
}
