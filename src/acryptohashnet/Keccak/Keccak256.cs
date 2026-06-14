using System;
using System.Numerics;

namespace acryptohashnet;

/// <summary>
/// Defined by 'Keccak implementation overview' article 
/// by Guido Bertoni, Joan Daeme, Michaël Peeters, Gilles Van Assche and Ronny Van Keer.
/// https://keccak.team/keccak.html
/// </summary>
public sealed class Keccak256 : BlockHashAlgorithm
{
    private readonly ulong[] state = new ulong[25];

    public Keccak256() : base(136)
    {
        HashSizeValue = 256;
    }

    public override void Initialize()
    {
        base.Initialize();
        state.AsSpan().Fill(0);
    }

    protected override void ProcessBlock(ReadOnlySpan<byte> block)
    {
        for (int ii = 0; ii < BlockSize / 8; ii += 1)
        {
            state[ii] ^= LittleEndian.ToUInt64(block.Slice(ii * 8, 8));
        }

        Keccak.Permute(state);
    }

    protected override byte[] ProcessFinalBlock()
    {
        return LittleEndian.ToByteArray(state.AsSpan(0, 4));
    }

    protected override byte[] GeneratePaddingBlocks(ReadOnlySpan<byte> lastBlock, BigInteger messageLength)
    {
        var padding = new byte[BlockSize];
        lastBlock.CopyTo(padding);

        padding[lastBlock.Length] = 0x01;    // 0000 0001
        padding[padding.Length - 1] |= 0x80; // 1000 0000

        return padding;
    }
}
