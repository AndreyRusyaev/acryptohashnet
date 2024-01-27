using System;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    internal static class StringUtils
    {
        public static byte[] GetUtf8Bytes(this string input) => Encoding.UTF8.GetBytes(input);

        public static string ToHexString(this byte[] bytes) => string.Join("", bytes.Select(x => x.ToString("x2")));
    }
}
