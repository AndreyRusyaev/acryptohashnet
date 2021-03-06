using System;

namespace acryptohashnet
{
    /// <summary>
    /// Tiger: A Fast New Cryptographic Hash Function (Designed in 1995)
    /// by Eli Biham & Ross Anderson
    /// https://www.cs.technion.ac.il/~biham/Reports/Tiger/
    /// </summary>
    public sealed class Tiger : TigerBase
    {
        public Tiger() : base(TigerPaddingMethod.MD4)
        {
        }
    }
}
