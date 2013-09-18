// ReSharper disable UnusedMember.Local
// ReSharper disable InconsistentNaming
using System.Linq;
using System.Security.Cryptography;
using Machine.Specifications;

namespace Murmur.Specs
{
    internal class Murmur128Specs
    {
        [Subject("Murmur128")]
        private class given_a_managed_x64_algorithm
        {
            private static readonly HashExpection Expectation = new HashExpection(128, 0x6384BA69);

            private static uint VerificationHash;

            private Establish context = () => VerificationHash = 0;

            private Because of =
                () =>
                    VerificationHash =
                        HashVerifier.ComputeVerificationHash(Expectation.Bits,
                            seed => MurmurHash.Create128(seed, true, AlgorithmPreference.X64));

            private It should_have_computed_correct_hash = () => VerificationHash.ShouldEqual(Expectation.Result);
        }

        [Subject("Murmur128")]
        private class given_an_unmanaged_x64_algorithm
        {
            private static readonly HashExpection Expectation = new HashExpection(128, 0x6384BA69);

            private static uint VerificationHash;

            private Establish context = () => VerificationHash = 0;

            private Because of =
                () =>
                    VerificationHash =
                        HashVerifier.ComputeVerificationHash(Expectation.Bits,
                            seed => MurmurHash.Create128(seed, false, AlgorithmPreference.X64));

            private It should_have_computed_correct_hash = () => VerificationHash.ShouldEqual(Expectation.Result);
        }

        [Subject("Murmur128")]
        private class given_a_managed_x86_algorithm
        {
            private static readonly HashExpection Expectation = new HashExpection(128, 0xB3ECE62A);

            private static uint VerificationHash;

            private Establish context = () => VerificationHash = 0;

            private Because of =
                () =>
                    VerificationHash =
                        HashVerifier.ComputeVerificationHash(Expectation.Bits,
                            seed => MurmurHash.Create128(seed, true, AlgorithmPreference.X86));

            private It should_have_computed_correct_hash = () => VerificationHash.ShouldEqual(Expectation.Result);
        }

        [Subject("Murmur128")]
        private class given_an_unmanaged_x86_algorithm
        {
            private static readonly HashExpection Expectation = new HashExpection(128, 0xB3ECE62A);

            private static uint VerificationHash;

            private Establish context = () => VerificationHash = 0;

            private Because of =
                () =>
                    VerificationHash =
                        HashVerifier.ComputeVerificationHash(Expectation.Bits,
                            seed => MurmurHash.Create128(seed, false, AlgorithmPreference.X86));

            private It should_have_computed_correct_hash = () => VerificationHash.ShouldEqual(Expectation.Result);
        }

        [Subject("Murmur128")]
        private class given_a_managed_and_unmanaged_algorithm
        {
            private static byte[] Input;

            private static HashAlgorithm Managed;

            private static HashAlgorithm Unmanaged;

            private static byte[] ManagedResult;

            private static byte[] UnmanagedResult;

            private Establish context = () =>
                {
                    Managed = MurmurHash.Create128();
                    Unmanaged = MurmurHash.Create128(managed: false);

                    Input = new byte[256*8];
                    using (var crypto = RandomNumberGenerator.Create())
                        crypto.GetNonZeroBytes(Input);
                };

            private Because of = () =>
                {
                    ManagedResult = Managed.ComputeHash(Input);
                    UnmanagedResult = Unmanaged.ComputeHash(Input);
                };

            private It should_have_generated_the_same_hash =
                () => ManagedResult.SequenceEqual(UnmanagedResult).ShouldBeTrue();

            private Cleanup cleanup = () =>
                {
                    Managed.Dispose();
                    Unmanaged.Dispose();
                };
        }
    }
}
// ReSharper restore InconsistentNaming
// ReSharper restore UnusedMember.Local