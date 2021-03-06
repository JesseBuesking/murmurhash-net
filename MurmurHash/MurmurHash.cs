﻿#pragma warning disable 1587
/// Copyright 2012 Darren Kopp
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
/// Unless required by applicable law or agreed to in writing, software
/// distributed under the License is distributed on an "AS IS" BASIS,
/// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
/// See the License for the specific language governing permissions and
/// limitations under the License.
#pragma warning restore 1587

using System;
using System.Security.Cryptography;

namespace Murmur
{
    public enum AlgorithmPreference
    {
        Auto,

        X64,

        X86
    }

    public static class MurmurHash
    {
// ReSharper disable UnusedMember.Global
        public static Murmur32 Create32(uint seed = 0, bool managed = true)
// ReSharper restore UnusedMember.Global
        {
            if (managed)
                return new Murmur32ManagedX86(seed);

            return new Murmur32UnmanagedX86(seed);
        }

// ReSharper disable UnusedMember.Global
        public static Murmur128 Create128(uint seed = 0, bool managed = true,
            AlgorithmPreference preference = AlgorithmPreference.Auto)
// ReSharper restore UnusedMember.Global
        {
            var algorithm = managed
                ? Pick(seed, preference, s => new Murmur128ManagedX86(s), s => new Murmur128ManagedX64(s))
                : Pick(seed, preference, s => new Murmur128UnmanagedX86(s), s => new Murmur128UnmanagedX64(s));

            return algorithm as Murmur128;
        }

        private static HashAlgorithm Pick<T32, T64>(uint seed, AlgorithmPreference preference, Func<uint, T32> factory32,
            Func<uint, T64> factory64)
            where T32 : HashAlgorithm
            where T64 : HashAlgorithm
        {
            switch (preference)
            {
                case AlgorithmPreference.X64:
                    return factory64(seed);
                case AlgorithmPreference.X86:
                    return factory32(seed);
                default:
                    {
                        if (Environment.Is64BitProcess)
                            return factory64(seed);

                        return factory32(seed);
                    }
            }
        }
    }
}