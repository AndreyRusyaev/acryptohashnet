using System;
using System.Linq;

namespace acryptohashnet.UnitTests
{
    internal static class StringUtils
    {
        public static string ToHexString(this byte[] bytes)
        {
            return string.Join("", bytes.Select(x => x.ToString("x2")));
        }
    }
}
