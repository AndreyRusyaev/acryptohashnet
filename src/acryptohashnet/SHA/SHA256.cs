namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// This is an alias of <see cref="Sha2_256" />. 
    /// It's provided only for backward compatibility with acryptohashnet < 3.0 and .Net Framework naming scheme.
    /// </summary>
    public sealed class SHA256: Sha2_256
    {
    }
}
