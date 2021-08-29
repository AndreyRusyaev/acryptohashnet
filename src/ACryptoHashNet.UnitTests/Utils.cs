﻿using System;

namespace Home.Andir.Cryptography
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
