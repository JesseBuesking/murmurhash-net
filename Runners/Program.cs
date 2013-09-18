using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Murmur;

namespace MurmurRunner
{
    internal class Program
    {
        private static readonly HashAlgorithm _unmanaged = MurmurHash.Create128(managed: false);

        private static readonly HashAlgorithm _managed = MurmurHash.Create128();

        private static readonly HashAlgorithm _unmanaged32 = MurmurHash.Create32(managed: false);

        private static readonly HashAlgorithm _managed32 = MurmurHash.Create32();

        private static readonly HashAlgorithm _sha1 = SHA1.Create();

        private static readonly HashAlgorithm _md5 = MD5.Create();

        private static readonly byte[] _randomData = GenerateRandomData();

        private static readonly byte[] _sampleData = CreateSampleData();

        private const int _fastIterationCount = 10000000;

        private const int _slowIterationCount = 100000;

        private static readonly IndentingConsoleWriter _outputWriter = new IndentingConsoleWriter();

        private static void Main()
        {
            _outputWriter.WriteLine("* Environment Architecture: {0}", Environment.Is64BitProcess ? "x64" : "x86");
            _outputWriter.NewLines();

            using (_outputWriter.Indent(2))
            {
                // guid output
                var guidSteps = new Dictionary<string, Tuple<HashAlgorithm, int>>
                    {
                        {"Murmur 32 Managed", Tuple.Create(_managed32, _fastIterationCount)},
                        {"Murmur 32 Unanaged", Tuple.Create(_unmanaged32, _fastIterationCount)},
                        {"Murmur 128 Managed", Tuple.Create(_managed, _fastIterationCount)},
                        {"Murmur 128 Unmanaged", Tuple.Create(_unmanaged, _fastIterationCount)},
                        {"SHA1", Tuple.Create(_sha1, _slowIterationCount)},
                        {"MD5", Tuple.Create(_md5, _slowIterationCount)}
                    };

                Run("Guid x 8", _sampleData.LongLength, a => a.ComputeHash(_sampleData), guidSteps);
                Run("Guid x 8 Partial", _sampleData.LongLength - 3, a => a.ComputeHash(_sampleData, 3, (int) (_sampleData.LongLength - 3)), guidSteps);

                // random data tests
                var randomSteps = new Dictionary<string, Tuple<HashAlgorithm, int>>
                    {
                        {"Murmur 32 Managed", Tuple.Create(_managed32, 2999)},
                        {"Murmur 32 Unanaged", Tuple.Create(_unmanaged32, 2999)},
                        {"Murmur 128 Managed", Tuple.Create(_managed, 2999)},
                        {"Murmur 128 Unmanaged", Tuple.Create(_unmanaged, 2999)},
                        {"SHA1", Tuple.Create(_sha1, 2999)},
                        {"MD5", Tuple.Create(_md5, 2999)}
                    };

                Run("Random", _randomData.LongLength, a => a.ComputeHash(_randomData), randomSteps);

                using (var stream = new MemoryStream(_randomData))
                {
                    Func<HashAlgorithm, byte[]> streamhasher = a =>
                        {
// ReSharper disable AccessToDisposedClosure
                            stream.Position = 0L;
                            return a.ComputeHash(stream);
// ReSharper restore AccessToDisposedClosure
                        };

                    Run("Stream", stream.Length, streamhasher, randomSteps);
                }
            }

            if (Debugger.IsAttached)
            {
                Console.WriteLine("Press any key to exit.");
                Console.Read();
            }
        }

        private static void Run(string name, long dataLength, Func<HashAlgorithm, byte[]> hasher,
            Dictionary<string, Tuple<HashAlgorithm, int>> steps)
        {
            _outputWriter.WriteLine("* Data Set: {0}", name);
            using (_outputWriter.Indent())
            {
                foreach (var step in steps)
                {
                    var algorithmFriendlyName = step.Key;
                    var algorithm = step.Value.Item1;
                    var iterations = step.Value.Item2;

                    _outputWriter.WriteLine("{1} x {0:N0}", iterations, algorithmFriendlyName);
                    Profile(algorithm, iterations, dataLength, hasher);
                }
            }
        }

        private static void Profile(HashAlgorithm algorithm, int iterations, long dataLength,
            Func<HashAlgorithm, byte[]> hasher)
        {
            using (_outputWriter.Indent())
            {
                var referenceHash = hasher(algorithm);
                //WriteProfilingResult("Runs", "{0:N0}", iterations);
                WriteProfilingResult("Output", GetHashAsString(referenceHash));

                // warmup
                for (int i = 0; i < 1000; i++)
                    hasher(algorithm);

                // profile
                var timer = Execute(algorithm, iterations, referenceHash, hasher);

                // results
                WriteProfilingResult("Length", "{0}   ", dataLength);
                WriteProfilingResult("Duration", "{0:N0} ms ({1:N0} ticks)", timer.ElapsedMilliseconds,
                    timer.ElapsedTicks);
                WriteProfilingResult("Ops/Tick", "{0:N3}", Divide(iterations, timer.ElapsedTicks));
                WriteProfilingResult("Ops/ms", "{0:N3}", Divide(iterations, timer.ElapsedMilliseconds));

                // calculate throughput
                WriteThroughput(dataLength, iterations, timer);
            }

            _outputWriter.NewLines();
        }

        private static Stopwatch Execute(HashAlgorithm algorithm, int iterations, byte[] expected,
            Func<HashAlgorithm, byte[]> hasher)
        {
            // capture our position
            int left = Console.CursorLeft;
            int top = Console.CursorTop;

            const int batches = 100;
            int batchSize = iterations/batches;
            var timer = Stopwatch.StartNew();
            for (int i = 0; i < batches; i++)
            {
                // write our progress
                WriteProfilingResult("Progress", "{0:P0}", Divide(i, batches));

                // run our batch
                for (int j = 0; j < batchSize; j++)
                {
                    var result = hasher(algorithm);
                    if (!Equal(expected, result))
                        throw new Exception("Received inconsistent hash.");
                }

                // reset cursor
                Console.SetCursorPosition(left, top);
            }

            // stop profiling
            timer.Stop();
            return timer;
        }

        private static void WriteThroughput(long length, long iterations, Stopwatch timer)
        {
            double totalBytes = length*iterations;
            double totalSeconds = timer.ElapsedMilliseconds/1000.0;

            double bytesPerSecond = totalBytes/totalSeconds;
            double mbitsPerSecond = (bytesPerSecond/(1024.0*1024.0));

            WriteProfilingResult("MiB/s", "{0:N3}", mbitsPerSecond);
        }

        private static bool Equal(byte[] expected, byte[] result)
        {
            if (expected.Length != result.Length) return false;
            return !expected.Where((t, i) => t != result[i]).Any();
        }

        private static double Divide(long a, long b)
        {
            return (a/(double) b);
        }

        private static void WriteProfilingResult(string name, string format = "{0}", params object[] args)
        {
            //var value = string.Format("* {0}:\t===>\t", name);
            var value = string.Format("* {0}:\t", name);
            _outputWriter.WriteLine(value + format, args);
        }

        private static string GetHashAsString(byte[] hash)
        {
            var builder = new StringBuilder(16);
            for (int i = 0; i < hash.Length; i++)
                builder.Append(hash[i].ToString("x2"));

            return builder.ToString();
        }

        public static byte[] Build(Guid[] values)
        {
            var target = new byte[values.Length*16];
            int offset = 0;
            foreach (var v in values)
            {
                Array.Copy(v.ToByteArray(), 0, target, offset, 16);
                offset += 16;
            }

            return target;
        }

        private static byte[] GenerateRandomData()
        {
            byte[] data = new byte[256*1024 + 13];
            using (var gen = RandomNumberGenerator.Create())
                gen.GetBytes(data);

            return data;
        }

        public static byte[] CreateSampleData()
        {
            var data = Build(new[]
                {
                    new Guid("1DB2A25C-57A3-471A-B81B-A01900A63F49"),
                    new Guid("24185DD0-1CB6-48EF-90A7-9F4A00D9BA0D"),
                    new Guid("6D21CDF4-70CC-4424-B72C-9F4A00D9BA0D"),
                    new Guid("6D194DF5-F28E-43B6-BBD2-9FB300D0CE52"),
                    new Guid("46F54EF7-5C8C-48C5-82EF-9F4A00D9BA0D"),
                    new Guid("DC34023A-A985-4EA2-BD22-9F4A00D9BA0D"),
                    new Guid("D12CAC55-E7C5-45D9-AE39-A0200092ACB0"),
                    new Guid("AD9EE455-27E2-4C0D-B3F1-9F4A00D9BA0D")
                });

            return data;
        }
    }

    internal class IndentingConsoleWriter
    {
        private int IndentAmount
        {
            get;
            set;
        }

        private string IndentString
        {
            get;
            set;
        }

        public void SetIndent(int value)
        {
            this.IndentAmount = value;
            this.IndentString = this.IndentAmount == 0 ? "" : new string(' ', this.IndentAmount);
        }

        public IDisposable Indent(int count = 4)
        {
            // create a new scope with current amount, then increment our indent
            var scope = new IndentationScope(this, this.IndentAmount);
            this.SetIndent(this.IndentAmount += count);

            return scope;
        }

        public void WriteLine(string format, params object[] args)
        {
            if (this.IndentAmount > 0)
                Console.Write(this.IndentString);

            Console.WriteLine(format, args);
        }

        public void NewLines(int count = 1)
        {
            for (int i = 0; i < count; i++)
                Console.WriteLine();
        }

        private class IndentationScope : IDisposable
        {
            private readonly IndentingConsoleWriter _writer;

            private readonly int _amount;

            public IndentationScope(IndentingConsoleWriter writer, int amount)
            {
                this._writer = writer;
                this._amount = amount;
            }

            public void Dispose()
            {
                // restore indent amount
                this._writer.SetIndent(this._amount);
            }
        }
    }
}