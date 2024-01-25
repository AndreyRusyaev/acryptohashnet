namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// This is an alias of <see cref="Sha2_512" />. 
    /// It's provided only for backward compatibility with acryptohashnet < 3.0 and .Net Framework naming scheme.
    /// </summary>
    public sealed class SHA512 : Sha2_512
    {
    }
}
