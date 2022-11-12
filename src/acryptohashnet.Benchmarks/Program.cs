using BenchmarkDotNet.Running;

namespace acryptohashnet.Benchmarks
{
    internal static class Program
    {
        static void Main(string[] args) => BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }
}
