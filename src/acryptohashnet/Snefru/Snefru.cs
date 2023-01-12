namespace acryptohashnet
{
    /// <summary>
    /// Ralph C. Merkle (1990). "A fast software one-way hash function"
    /// </summary>
    public sealed class Snefru : SnefruBase
    {
        public Snefru() : base(SnefruOutputSize.Output4)
        {
            HashSizeValue = 128;
        }
    }
}