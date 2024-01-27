# Overview
A pure C# implementation of cryptographic hash functions for .Net Standard 2.0 compatible platforms (.Net Framework, .Net Core, Mono, Xamarin, UWP, Unity).

# Features  

* Pure managed C# implementation,
* Compatible with System.Security.Cryptography.HashAlgorithm and can be used everywhere as a simple drop replacement for the target hash algorithm,
* Extremely fast, highly optimized with low memory footprint (less GC time).

# Implemented hash functions

* MD family: MD2, MD4, MD5,
* SHA family: SHA0, SHA1,
* SHA2 family: SHA224, SHA256, SHA384, SHA512,
* SHA3 family: SHA3-224, SHA3-256, SHA3-384, SHA3-512,
* RIPEMD family: RIPEMD128, RIPEMD160,
* Haval family: Haval128, Haval160, Haval192, Haval224, Haval256,
* Snefru, Snefru256,
* Tiger and Tiger2 (192 bits output)

# Usage examples

## Compute hashes with different algorithms and use of System.Security.Cryptography.HashAlgorithm

``` csharp
static class Program
{
    static void Main(string[] args)
    {
        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
          "print, and publishing industries for previewing layouts and visual mockups.";

        var md5 = new acryptohashnet.MD5();
        var sha1 = new acryptohashnet.SHA1();
        var sha2_256 = new acryptohashnet.Sha2_256();
        var sha3_512 = new acryptohashnet.Sha3_512();

        Console.WriteLine("message MD5: {0}", md5.ComputeHash(message.ToUtf8Bytes()).ToHexString());
        Console.WriteLine("message SHA1: {0}", sha1.ComputeHash(message.ToUtf8Bytes()).ToHexString());
        Console.WriteLine("message SHA256: {0}", sha2_256.ComputeHash(message.ToUtf8Bytes()).ToHexString());
        Console.WriteLine("message SHA3-512: {0}", sha3_512.ComputeHash(message.ToUtf8Bytes()).ToHexString());

        using (var file = File.OpenRead(@"C:\Windows\explorer.exe"))
        {
            Console.WriteLine("explorer.exe MD5: {0}", md5.ComputeHash(file).ToHexString());

            file.Position = 0; // Rewind stream to beginning
            Console.WriteLine("explorer.exe SHA1: {0}", sha1.ComputeHash(file).ToHexString());

            file.Position = 0; // Rewind stream to beginning
            Console.WriteLine("explorer.exe SHA256: {0}", sha2_256.ComputeHash(file).ToHexString());

            file.Position = 0; // Rewind stream to beginning
            Console.WriteLine("explorer.exe SHA3-512: {0}", sha3_512.ComputeHash(file).ToHexString());
        }
    }

    static byte[] ToUtf8Bytes(this string input) => System.Text.Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## MD5

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
    static void Main(string[] args)
    {
        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
            "print, and publishing industries for previewing layouts and visual mockups.";

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
        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
            "print, and publishing industries for previewing layouts and visual mockups.";

        var hashAlgorithm = new acryptohashnet.Sha2_512();
        Console.WriteLine("SHA256: {0}", hashAlgorithm.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA512 (SHA2-512 bits)

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
    static void Main(string[] args)
    {
        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
            "print, and publishing industries for previewing layouts and visual mockups.";

        var hashAlgorithm = new acryptohashnet.Sha2_512();
        Console.WriteLine("SHA512: {0}", hashAlgorithm.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA3-512

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
    static void Main(string[] args)
    {
        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
            "print, and publishing industries for previewing layouts and visual mockups.";

        var hashAlgorithm = new acryptohashnet.Sha3_512();
        Console.WriteLine("SHA3-512: {0}", hashAlgorithm.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

# Snefru256

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
    static void Main(string[] args)
    {
        var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
            "print, and publishing industries for previewing layouts and visual mockups.";

        var hashAlgorithm = new acryptohashnet.Snefru256();
        Console.WriteLine("Snefru256: {0}", hashAlgorithm.ComputeHash(message.ToUtf8Bytes()).ToHexString());
    }

    static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
    static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```