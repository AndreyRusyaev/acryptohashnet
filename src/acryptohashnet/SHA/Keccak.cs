using System;

namespace acryptohashnet
{
    internal static class Keccak
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
        public static void Permute(Span<ulong> state)
        {
            if (state.Length < 25)
            {
                throw new InvalidOperationException("State should be exactly 25 elements.");
            }

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

                    temp0 = state[0] ^ state[5] ^ state[10] ^ state[15] ^ state[20];
                    temp1 = state[1] ^ state[6] ^ state[11] ^ state[16] ^ state[21];
                    temp2 = state[2] ^ state[7] ^ state[12] ^ state[17] ^ state[22];
                    temp3 = state[3] ^ state[8] ^ state[13] ^ state[18] ^ state[23];
                    temp4 = state[4] ^ state[9] ^ state[14] ^ state[19] ^ state[24];

                    // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                    // A′[x, y, z] = A[x, y, z] ^ D[x, z].

                    // For all pairs (x, z) such that 0 ≤ x < 5 and 0 ≤ z < w let
                    // D[x, z] = C[(x - 1) mod 5, z] ^ C[(x + 1) mod 5, (z – 1) mod w].

                    // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                    // A′[x, y, z] = A[x, y, z] ^ D[x, z].
                    ulong d;

                    d = temp4 ^ temp1.RotateLeft(1);
                    state[0] ^= d; state[5] ^= d; state[10] ^= d; state[15] ^= d; state[20] ^= d;

                    d = temp0 ^ temp2.RotateLeft(1);
                    state[1] ^= d; state[6] ^= d; state[11] ^= d; state[16] ^= d; state[21] ^= d;

                    d = temp1 ^ temp3.RotateLeft(1);
                    state[2] ^= d; state[7] ^= d; state[12] ^= d; state[17] ^= d; state[22] ^= d;

                    d = temp2 ^ temp4.RotateLeft(1);
                    state[3] ^= d; state[8] ^= d; state[13] ^= d; state[18] ^= d; state[23] ^= d;

                    d = temp3 ^ temp0.RotateLeft(1);
                    state[4] ^= d; state[9] ^= d; state[14] ^= d; state[19] ^= d; state[24] ^= d;
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
                    // Precalculated indexes are
                    // piExchanges:
                    // 10, 07, 11, 17, 18, 03, 05, 16, 08, 21, 24, 04, 15, 23, 19, 13, 12, 02, 20, 14, 22, 09, 06, 01
                    // RhoRotations:
                    // 01, 03, 06, 10, 15, 21, 28, 36, 45, 55, 02, 14, 27, 41, 56, 08, 25, 43, 62, 18, 39, 61, 20, 44

                    ulong nextState = state[1];
                    temp0 = state[10]; state[10] = nextState.RotateLeft(01); nextState = temp0;
                    temp0 = state[07]; state[07] = nextState.RotateLeft(03); nextState = temp0;
                    temp0 = state[11]; state[11] = nextState.RotateLeft(06); nextState = temp0;
                    temp0 = state[17]; state[17] = nextState.RotateLeft(10); nextState = temp0;
                    temp0 = state[18]; state[18] = nextState.RotateLeft(15); nextState = temp0;
                    temp0 = state[03]; state[03] = nextState.RotateLeft(21); nextState = temp0;
                    temp0 = state[05]; state[05] = nextState.RotateLeft(28); nextState = temp0;
                    temp0 = state[16]; state[16] = nextState.RotateLeft(36); nextState = temp0;
                    temp0 = state[08]; state[08] = nextState.RotateLeft(45); nextState = temp0;
                    temp0 = state[21]; state[21] = nextState.RotateLeft(55); nextState = temp0;
                    temp0 = state[24]; state[24] = nextState.RotateLeft(02); nextState = temp0;
                    temp0 = state[04]; state[04] = nextState.RotateLeft(14); nextState = temp0;
                    temp0 = state[15]; state[15] = nextState.RotateLeft(27); nextState = temp0;
                    temp0 = state[23]; state[23] = nextState.RotateLeft(41); nextState = temp0;
                    temp0 = state[19]; state[19] = nextState.RotateLeft(56); nextState = temp0;
                    temp0 = state[13]; state[13] = nextState.RotateLeft(08); nextState = temp0;
                    temp0 = state[12]; state[12] = nextState.RotateLeft(25); nextState = temp0;
                    temp0 = state[02]; state[02] = nextState.RotateLeft(43); nextState = temp0;
                    temp0 = state[20]; state[20] = nextState.RotateLeft(62); nextState = temp0;
                    temp0 = state[14]; state[14] = nextState.RotateLeft(18); nextState = temp0;
                    temp0 = state[22]; state[22] = nextState.RotateLeft(39); nextState = temp0;
                    temp0 = state[09]; state[09] = nextState.RotateLeft(61); nextState = temp0;
                    temp0 = state[06]; state[06] = nextState.RotateLeft(20); nextState = temp0;
                    temp0 = state[01]; state[01] = nextState.RotateLeft(44); nextState = temp0;
                }

                // ### Chi

                // For all triples (x, y, z) such that 0 ≤ x < 5, 0 ≤ y < 5, and 0 ≤ z < w, let
                // A′ [x, y, z] = A[x, y, z] ^ ( ~A[(x + 1) mod 5, y, z] & A[(x + 2) mod 5, y, z] ).
                {
                    temp0 = state[0]; temp1 = state[1]; temp2 = state[2]; temp3 = state[3]; temp4 = state[4];

                    state[0] ^= ~temp1 & temp2;
                    state[1] ^= ~temp2 & temp3;
                    state[2] ^= ~temp3 & temp4;
                    state[3] ^= ~temp4 & temp0;
                    state[4] ^= ~temp0 & temp1;

                    temp0 = state[5]; temp1 = state[6]; temp2 = state[7]; temp3 = state[8]; temp4 = state[9];

                    state[5] ^= ~temp1 & temp2;
                    state[6] ^= ~temp2 & temp3;
                    state[7] ^= ~temp3 & temp4;
                    state[8] ^= ~temp4 & temp0;
                    state[9] ^= ~temp0 & temp1;

                    temp0 = state[10]; temp1 = state[11]; temp2 = state[12]; temp3 = state[13]; temp4 = state[14];

                    state[10] ^= ~temp1 & temp2;
                    state[11] ^= ~temp2 & temp3;
                    state[12] ^= ~temp3 & temp4;
                    state[13] ^= ~temp4 & temp0;
                    state[14] ^= ~temp0 & temp1;

                    temp0 = state[15]; temp1 = state[16]; temp2 = state[17]; temp3 = state[18]; temp4 = state[19];

                    state[15] ^= ~temp1 & temp2;
                    state[16] ^= ~temp2 & temp3;
                    state[17] ^= ~temp3 & temp4;
                    state[18] ^= ~temp4 & temp0;
                    state[19] ^= ~temp0 & temp1;

                    temp0 = state[20]; temp1 = state[21]; temp2 = state[22]; temp3 = state[23]; temp4 = state[24];

                    state[20] ^= ~temp1 & temp2;
                    state[21] ^= ~temp2 & temp3;
                    state[22] ^= ~temp3 & temp4;
                    state[23] ^= ~temp4 & temp0;
                    state[24] ^= ~temp0 & temp1;
                }

                // ### Iota

                // For all z such that 0 ≤ z < w, let A′ [0, 0, z] = A′ [0, 0, z] ^ RC[z].
                state[0] ^= RoundConstants[round];
            }
        }
    }
}
