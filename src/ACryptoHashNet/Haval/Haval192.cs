
namespace Home.Andir.Cryptography
{
    public sealed class Haval192 : HavalBase
    {
        public Haval192()
            : base(HavalHashSize.HashSize192, HavalPassCount.Pass5)
        { }

        public Haval192(HavalPassCount havalPassCount)
            : base(HavalHashSize.HashSize192, havalPassCount)
        { }
    }
}
