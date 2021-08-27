
namespace Home.Andir.Cryptography
{
    public sealed class Haval256 : HavalBase
    {
        public Haval256()
            : base(HavalHashSize.HashSize256, HavalPassCount.Pass5)
        { }

        public Haval256(HavalPassCount havalPassCount)
            : base(HavalHashSize.HashSize256, havalPassCount)
        { }
    }
}
