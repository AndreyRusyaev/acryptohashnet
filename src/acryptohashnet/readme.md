# Overview
A pure C# implementation of well-known cryptographic hash functions for .Net Standard 2.0 compatible platforms (.Net Framework, .Net Core, Mono, Xamarin, UWP, Unity).

# Included hash functions

* MD family: MD2, MD4, MD5,
* SHA family: SHA0, SHA1,
* SHA2 family: SHA224, SHA256, SHA384, SHA512,
* SHA3 family: SHA3_224, SHA3_256, SHA3_384, SHA3_512,
* RIPEMD family: RIPEMD128, RIPEMD160,
* Haval family: Haval128, Haval160, Haval192, Haval224, Haval256,
* Snefru, Snefru256,
* Tiger and Tiger2 (192 bits output)

# Usage examples

## Different algorithms with ToHexDigest extensions

``` csharp
using acryptohashnet;

var message = "Lorem ipsum is placeholder text commonly used in the graphic, " +
    "print, and publishing industries for previewing layouts and visual mockups.";

Console.WriteLine($"Message: '{message}'.");
Console.WriteLine($"MD5  128bit: {message.ToHexDigest(HashAlgorithms.Md5)}");
Console.WriteLine($"SHA1 160bit: {message.ToHexDigest(HashAlgorithms.Sha1)}");
Console.WriteLine($"SHA2 256bit: {message.ToHexDigest(HashAlgorithms.Sha2_256)}");
Console.WriteLine($"SHA3 256bit: {message.ToHexDigest(HashAlgorithms.Sha3_256)}");

using (var file = File.OpenRead(@"C:\Windows\explorer.exe"))
{
    Console.WriteLine($"explorer.exe SHA3 512bit: {file.ToHexDigest(HashAlgorithms.Sha3_512)}");
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
    var hashAlgorithm = new acryptohashnet.MD5();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
  }
  
   static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA2_256

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
  static void Main(string[] args)
  {
    var hashAlgorithm = new acryptohashnet.Sha2_256();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
  }
  
   static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA2_512

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
  static void Main(string[] args)
  {
    var hashAlgorithm = new acryptohashnet.Sha2_512();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
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
    var hashAlgorithm = new acryptohashnet.Snefru256();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
  }
  
   static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```