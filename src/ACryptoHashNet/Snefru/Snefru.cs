
namespace Home.Andir.Cryptography
{
    public sealed class Snefru : SnefruBase
    {
        public Snefru() : base(SnefruOutputSize.Output4)
        {
            this.HashSizeValue = 128;
        }
    }
}