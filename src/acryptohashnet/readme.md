# Overview
A pure C# implementation of well-known cryptographic hash functions for .Net Standard 2.0 compatible platforms (.Net Framework, .Net Core, Mono, Xamarin, UWP, Unity).

# Included hash functions

* MD family: MD2, MD4, MD5,
* SHA family: SHA0, SHA1,
* SHA2 family: SHA256, SHA384, SHA512,
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
    var hashAlgorithm = new acryptohashnet.MD5();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
  }
  
   static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA256

``` csharp
using System;
using System.Linq;
using System.Text;

static class Program
{
  static void Main(string[] args)
  {
    var hashAlgorithm = new acryptohashnet.SHA256();
    var hashBytes = hashAlgorithm.ComputeHash("message digest".ToUtf8Bytes());
    Console.WriteLine("Hash: {0}", hashBytes.ToHexString());
  }
  
   static byte[] ToUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);
   static string ToHexString(this byte[] input) => string.Join("", input.Select(x => x.ToString("x2")));
}
```

## SHA512

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