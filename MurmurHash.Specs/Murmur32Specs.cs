﻿// ReSharper disable UnusedMember.Local
// ReSharper disable InconsistentNaming
using System.Linq;
using System.Security.Cryptography;
using Machine.Specifications;

namespace Murmur.Specs
{
    internal class Murmur32Specs
    {
        [Subject("Murmur32")]
        private class given_a_managed_algorithm
        {
            private static readonly HashExpection Expectation = new HashExpection(32, 0xB0F57EE3);

            private static uint VerificationHash;

            private Establish context = () => VerificationHash = 0;

            private Because of =
                () =>
                    VerificationHash =
                        HashVerifier.ComputeVerificationHash(Expectation.Bits, seed => MurmurHash.Create32(seed));

            private It should_have_created_a_valid_hash = () => VerificationHash.ShouldEqual(Expectation.Result);
        }

        [Subject("Murmur32")]
        private class given_an_unmanaged_algorithm
        {
            private static readonly HashExpection Expectation = new HashExpection(32, 0xB0F57EE3);

            private static uint VerificationHash;

            private Establish context = () => VerificationHash = 0;

            private Because of =
                () =>
                    VerificationHash =
                        HashVerifier.ComputeVerificationHash(Expectation.Bits,
                            seed => MurmurHash.Create32(seed, managed: false));

            private It should_have_created_a_valid_hash = () => VerificationHash.ShouldEqual(Expectation.Result);
        }

        [Subject("Murmur32")]
        private class given_a_managed_and_unmanaged_algorithm
        {
            private static byte[] Input;

            private static HashAlgorithm Managed;

            private static HashAlgorithm Unmanaged;

            private static byte[] ManagedResult;

            private static byte[] UnmanagedResult;

            private Establish context = () =>
                {
                    Managed = MurmurHash.Create32();
                    Unmanaged = MurmurHash.Create32(managed: false);

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