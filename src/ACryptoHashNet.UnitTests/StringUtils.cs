using System;
using System.Linq;

namespace acryptohashnet.UnitTests
{
    internal static class StringUtils
    {
        public static string ByteArrayToHexString(byte[] array)
        {
            return string.Join("", array.Select(x => x.ToString("x2")));
        }
    }
}
