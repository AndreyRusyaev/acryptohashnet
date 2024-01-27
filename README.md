# acryptohashnet
A pure C# implementation of cryptographic hash functions for .Net Standard 2.0 compatible platforms (.Net Framework, .Net Core, Mono, Xamarin, UWP, Unity).

# Features  

* Pure managed C# implementation,
* Compatible with System.Security.Cryptography.HashAlgorithm and can be used everywhere as a simple drop replacement for the target hash algorithm,
* Extremely fast, highly optimized with low memory footprint (less GC time).

# Supported hash functions

* MD family: MD2, MD4, MD5,
* SHA family: SHA0, SHA1,
* SHA2 family: SHA224, SHA256, SHA384, SHA512,
* SHA3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512,
* RIPEMD family: RIPEMD128, RIPEMD160,
* Haval family: Haval128, Haval160, Haval192, Haval224, Haval256,
* Snefru, Snefru256,
* Tiger and Tiger2 (192 bits output)

# Usage examples

## MD5

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
    static void Main(string[] args)
    {
        var message = "Test Message";

        var hashAlgorithm = new acryptohashnet.MD5();
        Console.WriteLine("MD5: {0}", hashAlgorithm.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA256 (SHA2-256 bits)

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
    static void Main(string[] args)
    {
        var message = "Test Message";

        var hashAlgorithm = new acryptohashnet.Sha2_256();
        Console.WriteLine("SHA256: {0}", hashAlgorithm.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## Compute string message hash via HashAlgorithm interface (MD5, SHA1, SHA256, SHA3-512)

``` csharp
static class Program
{
    static void Main(string[] args)
    {
        var md5 = new acryptohashnet.MD5();
        var sha1 = new acryptohashnet.SHA1();
        var sha2_256 = new acryptohashnet.Sha2_256();
        var sha3_512 = new acryptohashnet.Sha3_512();

        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
                  "print, and publishing industries for previewing layouts and visual mockups.";

        Console.WriteLine("MD5: {0}", md5.ComputeHash(message.ToUtf8Bytes()).ToHexString());
        Console.WriteLine("SHA1: {0}", sha1.ComputeHash(message.ToUtf8Bytes()).ToHexString());
        Console.WriteLine("SHA256: {0}", sha2_256.ComputeHash(message.ToUtf8Bytes()).ToHexString());
        Console.WriteLine("SHA3-512: {0}", sha3_512.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => System.Text.Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## Compute hash of file via HashAlgorithm interface (MD5, SHA1, SHA256, SHA3-512)

``` csharp
static class Program
{
    static void Main(string[] args)
    {
        var md5 = new acryptohashnet.MD5();
        var sha1 = new acryptohashnet.SHA1();
        var sha2_256 = new acryptohashnet.Sha2_256();
        var sha3_512 = new acryptohashnet.Sha3_512();

        using (var file = File.OpenRead(@"C:\Windows\explorer.exe"))
        {
            Console.WriteLine("MD5: {0}", md5.ComputeHash(file).ToHexString());

            file.Position = 0; // Rewind stream to beginning
            Console.WriteLine("SHA1: {0}", sha1.ComputeHash(file).ToHexString());

            file.Position = 0; // Rewind stream to beginning
            Console.WriteLine("SHA256: {0}", sha2_256.ComputeHash(file).ToHexString());

            file.Position = 0; // Rewind stream to beginning
            Console.WriteLine("SHA3-512: {0}", sha3_512.ComputeHash(file).ToHexString());
        }
    }

    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

# Implamented hash algorithms

## MD Family
All functions designed and specified by [Ron Rivest](https://en.wikipedia.org/wiki/Ron_Rivest).
  * MD2, specification: [RFC 1319](docs/rfc1319.txt).
  * MD4, specification: [RFC 1320](docs/rfc1320.txt).
  * MD5, specification: [RFC 1321](docs/rfc1320.txt).

## SHA0 & SHA1
Secure Hash Standard [[pdf]](docs/NIST.FIPS.180-4.pdf)

## SHA2 Family
Secure Hash Standard [[pdf]](docs/NIST.FIPS.180-4.pdf)

Published as standard by "National Institute of Standards and Technology".

* SHA-0, 
* SHA-1,
* SHA2-224 (also known as SHA224),
* SHA2-256 (also known as SHA256),
* SHA2-384 (also known as SHA384),
* SHA2-512 (also known as SHA512)

## SHA3 Family
SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions [[pdf]](docs/NIST.FIPS.202.pdf)

Published as standard by "National Institute of Standards and Technology".

* SHA3-224,
* SHA3-256,
* SHA3-384,
* SHA3-512

## RIPEMD
RIPEMD-160: A Strengthened Version of RIPEMD [[pdf]](docs/AB-9601.pdf)

Designed by Hans Dobbertin, Antoon Bosselaers, [Bart Preneel](https://en.wikipedia.org/wiki/Bart_Preneel)

## Haval
HAVAL — A One-Way Hashing Algorithm with Variable Length of Output [[pdf]](docs/haval-paper.pdf)

Designed by Yuliang Zheng, Josef Pieprzyk and Jennifer Seberry.

## Snefru
A Fast Software One-Way Hash Function [[pdf]](docs/Merkle1990_Article_AFastSoftwareOne-wayHashFuncti.pdf)

Designed and specified by [Ralph C. Merkle](https://en.wikipedia.org/wiki/Ralph_Merkle).

## Tiger and Tiger2
[Tiger: A Fast New Hash Function](https://www.cs.technion.ac.il/~biham/Reports/Tiger/) [[ps]](docs/tiger.ps) [[pdf]](docs/tiger.pdf)

Designed and specified by [Ross Anderson](https://en.wikipedia.org/wiki/Ross_J._Anderson) and [Eli Biham](https://en.wikipedia.org/wiki/Eli_Biham).

# History
Originally project was developed between 2006-2009 as an open source project and was hosted on SourceForge: https://sourceforge.net/projects/acryptohashnet/.
In 2020 was migrated to Github and modernized for support .Net Core platform.

# Used by commercial and open source software

* Motorola RM Software
* Quest Software [Metalogix Archive Manager for Exchange](https://support.quest.com/technical-documents/metalogix-archive-manager-for-exchange/8.5/release-notes/5)
* Soft EtherConfig Password Node Generator https://github.com/SecretNest/SoftEtherConfigPasswordNodeGenerate
* Microsoft .NET wrapper for connecting to EMC Atmos Storage Service https://github.com/EMCECS/atmos-dotnet
* iTextSharp unofficial .Net Core port https://github.com/VahidN/iTextSharp.LGPLv2.Core
* UnityClassNameHasher https://github.com/OptoCloud/UnityClassNameHasher
