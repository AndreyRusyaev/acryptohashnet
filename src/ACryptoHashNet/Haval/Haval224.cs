
namespace acryptohashnet
{
    public sealed class Haval224 : HavalBase
    {
        public Haval224()
            : base(HavalHashSize.HashSize224, HavalPassCount.Pass5)
        {
        }

        public Haval224(HavalPassCount havalPassCount)
            : base(HavalHashSize.HashSize224, havalPassCount)
        {
        }
    }
}
