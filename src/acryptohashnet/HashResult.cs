using System;
using System.Linq;

namespace acryptohashnet;

public readonly struct HashResult(byte[] bytes)
{
    public byte[] Bytes { get; } = bytes;

    public string ToHex() => string.Join("", Bytes.Select(x => x.ToString("x2")));

    public string ToBase64() => Convert.ToBase64String(Bytes);

    override public string ToString() => ToHex();
}