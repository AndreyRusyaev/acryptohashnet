using System;

using BenchmarkDotNet.Running;

namespace acryptohashnet.Benchmarks
{
    class Program
    {
        static void Main(string[] args) => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }
}
