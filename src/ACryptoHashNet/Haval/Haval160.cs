
namespace Home.Andir.Cryptography
{
    public sealed class Haval160 : HavalBase
    {
        public Haval160()
            : base(HavalHashSize.HashSize160, HavalPassCount.Pass5)
        { }

        public Haval160(HavalPassCount havalPassCount)
            : base(HavalHashSize.HashSize160, havalPassCount)
        { }
    }
}
