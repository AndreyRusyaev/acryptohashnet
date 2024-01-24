using System;

namespace acryptohashnet
{
    internal static class KeccakPermutation
    {
        private static readonly ulong[] RoundConstants = new ulong[24]
        {
            0x0000000000000001UL, 0x0000000000008082UL,
            0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL,
            0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL,
            0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL,
            0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL,
            0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL,
            0x0000000080000001UL, 0x8000000080008008UL
        };
        public static void Run(Span<ulong> state, int rounds)
        {
            // w is 64 == sizeof(ulong)
            // 0 <= x < 5, 0 <= y < 5, 0 <= z < w
            // A is [5 x 5 x w]
            // A[x, y, z] = State[ w * (5y + x) + z]

            ulong[] temp = new ulong[25];

            for (int round = 0; round < rounds; round++)
            {
                // ### Theta

                // For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
                // C[x, z] = A[x, 0, z] ^ A[x, 1, z] ^ A[x, 2, z] ^ A[x, 3, z] ^ A[x, 4, z].
                for (int x = 0; x < 5; x += 1)
                {
                    temp[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
                }

                // For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
                // D[x, z] = C[(x - 1) mod 5, z] ^ C[(x + 1) mod 5, (z – 1) mod w].
                ulong[] d = new ulong[5];
                for (int x = 0; x < 5; x += 1)
                {
                    d[x] = temp[(x + 4) % 5] ^ temp[(x + 1) % 5].RotateLeft(1);
                }

                // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                // A′[x, y, z] = A[x, y, z] ^ D[x, z].
                for (int x = 0; x < 5; x += 1)
                {
                    for (int y = 0; y < 5; y += 1)
                    {
                        state[5 * y + x] ^= d[x];
                    }
                }

                // ### Rho

                // For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A[0, 0, z].
                // Let (x, y) = (1, 0).
                {
                    int x = 1;
                    int y = 0;
                    for (int t = 0; t < 24; t += 1)
                    {
                        // for all z such that 0 ≤ z < w, let A′[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod w];
                        int rotate = ((t + 1) * (t + 2) / 2) % 64;
                        state[y * 5 + x] = state[y * 5 + x].RotateLeft(rotate);
                        // let (x, y) = (y, (2x + 3y) mod 5).
                        int newY = (2 * x + 3 * y) % 5;
                        x = y;
                        y = newY;
                    }
                }

                // ### Pi

                // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                // A′[x, y, z] = A[(x + 3y) mod 5, x, z].
                for (int x = 0; x < 5; x += 1)
                {
                    for (int y = 0; y < 5; y += 1)
                    {
                        int prevX = (x + 3 * y) % 5;
                        int prevY = x;
                        temp[y * 5 + x] = state[prevY * 5 + prevX];
                    }
                }

                for (int ii = 0; ii < 25; ii += 1)
                {
                    state[ii] = temp[ii];
                }

                // ### Chi

                // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                // A′ [x, y, z] = A[x, y, z] ^ ( ~A[(x + 1) mod 5, y, z] & A[(x + 2) mod 5, y, z] ).
                for (int y = 0; y < 5; y += 1)
                {
                    for (int x = 0; x < 5; x++)
                    {
                        temp[x] = state[y * 5 + x];
                    }

                    for (int x = 0; x < 5; x++)
                    {
                        state[y * 5 + x] ^= (~temp[(x + 1) % 5]) & temp[(x + 2) % 5];
                    }
                }

                // ### Iota
                state[0] ^= RoundConstants[round];
            }
        }
    }
}
