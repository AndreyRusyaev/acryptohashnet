namespace acryptohashnet
{
    public enum PaddingType
    {
        Custom,
        OneZeroFillAnd8BytesMessageLengthLittleEndian,
        OneZeroFillAnd8BytesMessageLengthBigEndian,
        OneZeroFillAnd16BytesMessageLengthBigEndian
    }
}
