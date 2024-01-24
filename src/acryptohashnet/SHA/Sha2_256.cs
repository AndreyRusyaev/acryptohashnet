using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// </summary>
    public class Sha2_256 : BlockHashAlgorithm
    {
        private static readonly uint[] Constants = new uint[64]
        {
            // round 1
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            // round 2
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            // round 3
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            // round 4
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            // round 5
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            // round 6
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            // round 7
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            // round 8
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        private readonly HashState state = new HashState();

        private readonly uint[] buffer = new uint[64];

        public Sha2_256() : base(64)
        {
            PaddingType = PaddingType.OneZeroFillAnd8BytesMessageLengthBigEndian;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.Initialize();
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            // Fill buffer for transformation
            BigEndian.Copy(block, buffer.AsSpan(0, 16));

            for (int ii = 16; ii < buffer.Length; ii++)
            {
                buffer[ii] = SHAFunctions32.Ro1(buffer[ii - 2]) + buffer[ii - 7] + SHAFunctions32.Ro0(buffer[ii - 15]) + buffer[ii - 16];
            }

            uint a = state.A;
            uint b = state.B;
            uint c = state.C;
            uint d = state.D;
            uint e = state.E;
            uint f = state.F;
            uint g = state.G;
            uint h = state.H;

            for (int ii = 0; ii < buffer.Length - 7; ii += 8)
            {
                // step 1
                h += buffer[ii + 0] + Constants[ii + 0] + SHAFunctions32.Ch(e, f, g) + SHAFunctions32.Sig1(e);
                d += h;
                h += SHAFunctions32.Maj(a, b, c) + SHAFunctions32.Sig0(a);

                // step 2
                g += buffer[ii + 1] + Constants[ii + 1] + SHAFunctions32.Ch(d, e, f) + SHAFunctions32.Sig1(d);
                c += g;
                g += SHAFunctions32.Maj(h, a, b) + SHAFunctions32.Sig0(h);

                // step 3
                f += buffer[ii + 2] + Constants[ii + 2] + SHAFunctions32.Ch(c, d, e) + SHAFunctions32.Sig1(c);
                b += f;
                f += SHAFunctions32.Maj(g, h, a) + SHAFunctions32.Sig0(g);

                // step 4
                e += buffer[ii + 3] + Constants[ii + 3] + SHAFunctions32.Ch(b, c, d) + SHAFunctions32.Sig1(b);
                a += e;
                e += SHAFunctions32.Maj(f, g, h) + SHAFunctions32.Sig0(f);

                // step 5
                d += buffer[ii + 4] + Constants[ii + 4] + SHAFunctions32.Ch(a, b, c) + SHAFunctions32.Sig1(a);
                h += d;
                d += SHAFunctions32.Maj(e, f, g) + SHAFunctions32.Sig0(e);

                // step 6
                c += buffer[ii + 5] + Constants[ii + 5] + SHAFunctions32.Ch(h, a, b) + SHAFunctions32.Sig1(h);
                g += c;
                c += SHAFunctions32.Maj(d, e, f) + SHAFunctions32.Sig0(d);

                // step 7
                b += buffer[ii + 6] + Constants[ii + 6] + SHAFunctions32.Ch(g, h, a) + SHAFunctions32.Sig1(g);
                f += b;
                b += SHAFunctions32.Maj(c, d, e) + SHAFunctions32.Sig0(c);

                // step 8
                a += buffer[ii + 7] + Constants[ii + 7] + SHAFunctions32.Ch(f, g, h) + SHAFunctions32.Sig1(f);
                e += a;
                a += SHAFunctions32.Maj(b, c, d) + SHAFunctions32.Sig0(b);
            }

            state.A += a;
            state.B += b;
            state.C += c;
            state.D += d;
            state.E += e;
            state.F += f;
            state.G += g;
            state.H += h;
        }

        protected override byte[] ProcessFinalBlock()
        {
            return state.ToByteArray();
        }

        private sealed class HashState
        {
            public uint A;
            public uint B;
            public uint C;
            public uint D;
            public uint E;
            public uint F;
            public uint G;
            public uint H;

            public HashState()
            {
                Initialize();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Initialize()
            {
                A = 0x6a09e667;
                B = 0xbb67ae85;
                C = 0x3c6ef372;
                D = 0xa54ff53a;
                E = 0x510e527f;
                F = 0x9b05688c;
                G = 0x1f83d9ab;
                H = 0x5be0cd19;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public byte[] ToByteArray()
            {
                var result = new byte[32];

                BigEndian.Copy(A, result);
                BigEndian.Copy(B, result.AsSpan(4));
                BigEndian.Copy(C, result.AsSpan(8));
                BigEndian.Copy(D, result.AsSpan(12));
                BigEndian.Copy(E, result.AsSpan(16));
                BigEndian.Copy(F, result.AsSpan(20));
                BigEndian.Copy(G, result.AsSpan(24));
                BigEndian.Copy(H, result.AsSpan(28));

                return result;
            }
        }
    }
}
