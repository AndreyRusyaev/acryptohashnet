using System;

namespace acryptohashnet
{
    internal static class KeccakPermutation
    {
        private static readonly ulong[] RoundConstants = new ulong[24]
        {
            0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808a, 0x8000_0000_8000_8000,
            0x0000_0000_0000_808b, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
            0x0000_0000_0000_008a, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000a,
            0x0000_0000_8000_808b, 0x8000_0000_0000_008b, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
            0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800a, 0x8000_0000_8000_000a,
            0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008
        };

        private static readonly int[] RhoRotations = new int[24]
        {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
        };

        private static readonly int[] piExchanges = new int[24]
        {
            10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
        };
        public static void Run(Span<ulong> state)
        {
            // w is 64 == sizeof(ulong)
            // 0 <= x < 5, 0 <= y < 5, 0 <= z < w
            // A is [5 x 5 x w]
            // A[x, y, z] = State[ w * (5y + x) + z ]

            ulong temp0;
            ulong temp1;
            ulong temp2;
            ulong temp3;
            ulong temp4;

            for (int round = 0; round < RoundConstants.Length; round += 1)
            {
                // ### Theta

                {
                    // For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w, let
                    // C[x, z] = A[x, 0, z] ^ A[x, 1, z] ^ A[x, 2, z] ^ A[x, 3, z] ^ A[x, 4, z].

                    temp0 = state[0] ^ state[0 + 5] ^ state[0 + 10] ^ state[0 + 15] ^ state[0 + 20];
                    temp1 = state[1] ^ state[1 + 5] ^ state[1 + 10] ^ state[1 + 15] ^ state[1 + 20];
                    temp2 = state[2] ^ state[2 + 5] ^ state[2 + 10] ^ state[2 + 15] ^ state[2 + 20];
                    temp3 = state[3] ^ state[3 + 5] ^ state[3 + 10] ^ state[3 + 15] ^ state[3 + 20];
                    temp4 = state[4] ^ state[4 + 5] ^ state[4 + 10] ^ state[4 + 15] ^ state[4 + 20];

                    // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                    // A′[x, y, z] = A[x, y, z] ^ D[x, z].

                    // For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
                    // D[x, z] = C[(x - 1) mod 5, z] ^ C[(x + 1) mod 5, (z – 1) mod w].

                    // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                    // A′[x, y, z] = A[x, y, z] ^ D[x, z].
                    ulong d;
                    
                    d = temp4 ^ temp1.RotateLeft(1);
                    state[0 + 0] ^= d; state[0 + 5] ^= d; state[0 + 10] ^= d; state[0 + 15] ^= d; state[0 + 20] ^= d;

                    d = temp0 ^ temp2.RotateLeft(1);
                    state[1 + 0] ^= d; state[1 + 5] ^= d; state[1 + 10] ^= d; state[1 + 15] ^= d; state[1 + 20] ^= d;

                    d = temp1 ^ temp3.RotateLeft(1);
                    state[2 + 0] ^= d; state[2 + 5] ^= d; state[2 + 10] ^= d; state[2 + 15] ^= d; state[2 + 20] ^= d;

                    d = temp2 ^ temp4.RotateLeft(1);
                    state[3 + 0] ^= d; state[3 + 5] ^= d; state[3 + 10] ^= d; state[3 + 15] ^= d; state[3 + 20] ^= d;

                    d = temp3 ^ temp0.RotateLeft(1);
                    state[4 + 0] ^= d; state[4 + 5] ^= d; state[4 + 10] ^= d; state[4 + 15] ^= d; state[4 + 20] ^= d;
                }

                // ### Rho + Pi (combined steps with predcalculated indexes)

                // Rho:
                // For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A[0, 0, z].
                // Let (x, y) = (1, 0).
                // For t from 0 to 23:
                //     for all z such that 0 ≤ z < w, let A′[x, y, z] = A[x, y, (z – (t + 1)(t + 2)/2) mod w];
                //     let (x, y) = (y, (2x + 3y) mod 5).
                // End For

                // Pi:
                // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                // A′[x, y, z] = A[(x + 3y) mod 5, x, z].
                {
                    ulong nextState = state[piExchanges[piExchanges.Length - 1]];
                    for (int ii = 0; ii < 24; ii += 1)
                    {
                        int nextIndex = piExchanges[ii];

                        ulong prevState = state[nextIndex];
                        state[nextIndex] = nextState.RotateLeft(RhoRotations[ii]);
                        nextState = prevState;
                    }
                }

                // ### Chi

                // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                // A′ [x, y, z] = A[x, y, z] ^ ( ~A[(x + 1) mod 5, y, z] & A[(x + 2) mod 5, y, z] ).
                for (int ii = 0; ii < state.Length - 4; ii += 5)
                {
                    temp0 = state[ii + 0];
                    temp1 = state[ii + 1];
                    temp2 = state[ii + 2];
                    temp3 = state[ii + 3];
                    temp4 = state[ii + 4];

                    state[ii + 0] ^= ~temp1 & temp2;
                    state[ii + 1] ^= ~temp2 & temp3;
                    state[ii + 2] ^= ~temp3 & temp4;
                    state[ii + 3] ^= ~temp4 & temp0;
                    state[ii + 4] ^= ~temp0 & temp1;
                }

                // ### Iota

                // For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ^ RC[z].
                state[0] ^= RoundConstants[round];
            }
        }
    }
}
