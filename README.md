# acryptohashnet
A pure C# implementation of well-known cryptographic hash functions for .Net Standard 2.0 compatible platforms (.Net Framework, .Net Core, Mono, Xamarin, UWP, Unity).

# Features  
  * Pure managed implementations,
  * Compatible with System.Security.Cryptography.HashAlgorithm and can be used everywhere as a simple replacement of the target hash algorithm,
  * Fast and has low memory footprint (less GC).

# Usage examples

## MD5 of file
``` csharp
using System;
using System.IO;
using System.Linq;

static class Program
{
  static void Main(string[] args)
  {
    var hashAlgorithm = new acryptohashnet.MD5();

    using(var stream = File.OpenRead(@"C:\Windows\System32\explorer.exe"))
    {
      var hashBytes = hashAlgorithm.ComputeHash(stream);
      Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
    }
  }

   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA512 of string

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
  static void Main(string[] args)
  {
    var hashAlgorithm = new acryptohashnet.SHA512();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
  }
  
   static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

# Implemented hash functions

## MD Family
All functions designed and specified by [Ron Rivest](https://en.wikipedia.org/wiki/Ron_Rivest).
  * MD2, specification: [RFC 1319](docs/rfc1319.txt).
  * MD4, specification: [RFC 1320](docs/rfc1320.txt).
  * MD5, specification: [RFC 1321](docs/rfc1320.txt).

## SHA Family
Secure Hash Standard [[pdf]](docs/fips180-3_final.pdf)

Published as standard by "National Institute of Standards and Technology".

* SHA-0, 
* SHA-1,
* SHA-256,
* SHA-384,
* SHA-512

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
