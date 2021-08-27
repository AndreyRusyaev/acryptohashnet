using System;

namespace Home.Andir.Cryptography
{
    public static class BigEndianBuffer
    {
        public static void BlockCopy(uint[] src, int srcOffset, byte[] dst, int dstOffset, int countBytes)
        {
            int countUints = countBytes >> 2; // arg / 4
            int lastCountBytes = countBytes & 0x3; // arg % 4

            for (int ii = 0; ii < countUints; ii++)
                for (int jj = 0; jj < 4; jj++)
                    dst[dstOffset + (ii << 2) + jj] = (byte)(src[srcOffset + ii] >> (24 - (jj << 3)));


            for (int jj = 0; jj < lastCountBytes; jj++)
                dst[(countUints << 2) + jj] = (byte)(src[srcOffset + countUints] >> (24 - (jj << 3)));
        }

        public static void BlockCopy(byte[] src, int srcOffset, uint[] dst, int dstOffset, int countBytes)
        {
            int countUints = countBytes >> 2; // arg / 4
            int lastCountBytes = countBytes & 0x3; // arg % 4

            for (int ii = 0; ii < countUints; ii++)
            {
                dst[dstOffset + ii] = 0;
                for (int jj = 0; jj < 4; jj++)
                    dst[dstOffset + ii] |= (uint)(src[srcOffset + (ii << 2) + jj]) << (24 - (jj << 3));
            }

            if (lastCountBytes > 0)
            {
                dst[dstOffset + countUints] = 0;
                for (int jj = 0; jj < lastCountBytes; jj++)
                    dst[dstOffset + countUints] |= (uint)(src[srcOffset + (countUints << 2) + jj]) << (24 - (jj << 3));
            }
        }

        public static void BlockCopy(ulong[] src, int srcOffset, byte[] dst, int dstOffset, int countBytes)
        {
            int countUlongs = countBytes >> 3; // arg / 8
            int lastCountBytes = countBytes & 0x7; // arg % 8

            for (int ii = 0; ii < countUlongs; ii++)
                for (int jj = 0; jj < 8; jj++)
                    dst[dstOffset + (ii << 3) + jj] = (byte)(src[srcOffset + ii] >> (56 - (jj << 3)));

            for (int jj = 0; jj < lastCountBytes; jj++)
                dst[(countUlongs << 3) + jj] = (byte)(src[srcOffset + countUlongs] >> (56 - (jj << 3)));
        }

        public static void BlockCopy(byte[] src, int srcOffset, ulong[] dst, int dstOffset, int countBytes)
        {
            int countUlongs = countBytes >> 3; // arg / 8
            int lastCountBytes = countBytes & 0x7; // arg % 8

            for (int ii = 0; ii < countUlongs; ii++)
            {
                dst[dstOffset + ii] = 0;
                for (int jj = 0; jj < 8; jj++)
                    dst[dstOffset + ii] |= (ulong)(src[srcOffset + (ii << 3) + jj]) << (56 - (jj << 3));
            }

            if (lastCountBytes > 0)
            {
                dst[dstOffset + countUlongs] = 0;
                for (int jj = 0; jj < lastCountBytes; jj++)
                    dst[dstOffset + countUlongs] |= (ulong)(src[srcOffset + (countUlongs << 3) + jj]) << (56 - (jj << 3));
            }
        }
    }
}
