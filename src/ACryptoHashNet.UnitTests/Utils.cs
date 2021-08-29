using System;

namespace acryptohashnet
{
    public static class Utils
    {
        public static string ByteArrayToHexString(byte[] array)
        {
            return string.Join(
                "", 
                Array.ConvertAll(array, x => x.ToString("x2")));
        }
    }
}
