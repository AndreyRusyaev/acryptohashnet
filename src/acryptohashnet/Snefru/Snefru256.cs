namespace acryptohashnet
{
    public sealed class Snefru256 : SnefruBase
    {
        public Snefru256(): base(SnefruOutputSize.Output8)
        {
            HashSizeValue = 256;
        }
    }
}