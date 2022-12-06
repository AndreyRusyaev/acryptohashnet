using System;
using System.Runtime.CompilerServices;

namespace acryptohashnet
{
    /// <summary>
    /// Defined by FIPS 180-4: Secure Hash Standard (SHS)
    /// </summary>
    public sealed class SHA512 : BlockHashAlgorithm
    {
        private static readonly ulong[] Constants = new ulong[]
        {
            // round 1
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            // round 2
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            // round 3
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            // round 4
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            // round 5
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            // round 6
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            // round 7
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            // round 8
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            // round 9
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            // round 10
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
        };

        private readonly HashState state = new HashState();

        private readonly ulong[] buffer = new ulong[80];

        public SHA512() : base(128)
        {
            PaddingType = PaddingType.OneZeroFillAnd16BytesMessageLengthBigEndian;
        }

        public override void Initialize()
        {
            base.Initialize();
            state.Initialize();
        }

        protected override void ProcessBlock(ReadOnlySpan<byte> block)
        {
            BigEndian.Copy(block, buffer.AsSpan(0, 16));

            // Extend buffer
            for (int ii = 16; ii < buffer.Length - 7; ii += 8)
            {
                buffer[ii + 0] = SHAFunctions64.Ro1(buffer[ii - 2]) + buffer[ii - 7] + SHAFunctions64.Ro0(buffer[ii - 15]) + buffer[ii - 16];
                buffer[ii + 1] = SHAFunctions64.Ro1(buffer[ii - 1]) + buffer[ii - 6] + SHAFunctions64.Ro0(buffer[ii - 14]) + buffer[ii - 15];
                buffer[ii + 2] = SHAFunctions64.Ro1(buffer[ii - 0]) + buffer[ii - 5] + SHAFunctions64.Ro0(buffer[ii - 13]) + buffer[ii - 14];
                buffer[ii + 3] = SHAFunctions64.Ro1(buffer[ii + 1]) + buffer[ii - 4] + SHAFunctions64.Ro0(buffer[ii - 12]) + buffer[ii - 13];
                buffer[ii + 4] = SHAFunctions64.Ro1(buffer[ii + 2]) + buffer[ii - 3] + SHAFunctions64.Ro0(buffer[ii - 11]) + buffer[ii - 12];
                buffer[ii + 5] = SHAFunctions64.Ro1(buffer[ii + 3]) + buffer[ii - 2] + SHAFunctions64.Ro0(buffer[ii - 10]) + buffer[ii - 11];
                buffer[ii + 6] = SHAFunctions64.Ro1(buffer[ii + 4]) + buffer[ii - 1] + SHAFunctions64.Ro0(buffer[ii - 09]) + buffer[ii - 10];
                buffer[ii + 7] = SHAFunctions64.Ro1(buffer[ii + 5]) + buffer[ii - 0] + SHAFunctions64.Ro0(buffer[ii - 08]) + buffer[ii - 09];
            }

            ulong a = state.A;
            ulong b = state.B;
            ulong c = state.C;
            ulong d = state.D;
            ulong e = state.E;
            ulong f = state.F;
            ulong g = state.G;
            ulong h = state.H;

            for (int ii = 0; ii < buffer.Length - 7; ii += 8)
            {
                // step 1
                h += buffer[ii + 0] + Constants[ii + 0] + SHAFunctions64.Ch(e, f, g) + SHAFunctions64.Sig1(e);
                d += h;
                h += SHAFunctions64.Maj(a, b, c) + SHAFunctions64.Sig0(a);

                // step 2
                g += buffer[ii + 1] + Constants[ii + 1] + SHAFunctions64.Ch(d, e, f) + SHAFunctions64.Sig1(d);
                c += g;
                g += SHAFunctions64.Maj(h, a, b) + SHAFunctions64.Sig0(h);

                // step 3
                f += buffer[ii + 2] + Constants[ii + 2] + SHAFunctions64.Ch(c, d, e) + SHAFunctions64.Sig1(c);
                b += f;
                f += SHAFunctions64.Maj(g, h, a) + SHAFunctions64.Sig0(g);

                // step 4
                e += buffer[ii + 3] + Constants[ii + 3] + SHAFunctions64.Ch(b, c, d) + SHAFunctions64.Sig1(b);
                a += e;
                e += SHAFunctions64.Maj(f, g, h) + SHAFunctions64.Sig0(f);

                // step 5
                d += buffer[ii + 4] + Constants[ii + 4] + SHAFunctions64.Ch(a, b, c) + SHAFunctions64.Sig1(a);
                h += d;
                d += SHAFunctions64.Maj(e, f, g) + SHAFunctions64.Sig0(e);

                // step 6
                c += buffer[ii + 5] + Constants[ii + 5] + SHAFunctions64.Ch(h, a, b) + SHAFunctions64.Sig1(h);
                g += c;
                c += SHAFunctions64.Maj(d, e, f) + SHAFunctions64.Sig0(d);

                // step 7
                b += buffer[ii + 6] + Constants[ii + 6] + SHAFunctions64.Ch(g, h, a) + SHAFunctions64.Sig1(g);
                f += b;
                b += SHAFunctions64.Maj(c, d, e) + SHAFunctions64.Sig0(c);

                // step 8
                a += buffer[ii + 7] + Constants[ii + 7] + SHAFunctions64.Ch(f, g, h) + SHAFunctions64.Sig1(f);
                e += a;
                a += SHAFunctions64.Maj(b, c, d) + SHAFunctions64.Sig0(b);
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
            public ulong A;
            public ulong B;
            public ulong C;
            public ulong D;
            public ulong E;
            public ulong F;
            public ulong G;
            public ulong H;

            public HashState()
            {
                Initialize();
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public void Initialize()
            {
                A = 0x6a09e667f3bcc908;
                B = 0xbb67ae8584caa73b;
                C = 0x3c6ef372fe94f82b;
                D = 0xa54ff53a5f1d36f1;
                E = 0x510e527fade682d1;
                F = 0x9b05688c2b3e6c1f;
                G = 0x1f83d9abfb41bd6b;
                H = 0x5be0cd19137e2179;
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public byte[] ToByteArray()
            {
                var result = new byte[64];

                BigEndian.Copy(A, result);
                BigEndian.Copy(B, result.AsSpan(8));
                BigEndian.Copy(C, result.AsSpan(16));
                BigEndian.Copy(D, result.AsSpan(24));
                BigEndian.Copy(E, result.AsSpan(32));
                BigEndian.Copy(F, result.AsSpan(40));
                BigEndian.Copy(G, result.AsSpan(48));
                BigEndian.Copy(H, result.AsSpan(56));

                return result;
            }
        }
    }
}
