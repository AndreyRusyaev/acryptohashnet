using System;

namespace acryptohashnet
{
    /// <summary>
    /// Tiger: A Fast New Cryptographic Hash Function (Designed in 1995)
    /// by Eli Biham & Ross Anderson
    /// https://www.cs.technion.ac.il/~biham/Reports/Tiger/
    /// Difference with Tiger only in padding method
    /// </summary>
    public sealed class Tiger2 : TigerBase
    {
        public Tiger2() : base()
        {
            PaddingType = PaddingType.OneZeroFillAnd8BytesMessageLengthLittleEndian;
        }
    }
}
