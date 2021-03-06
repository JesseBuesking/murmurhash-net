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

using System.Security.Cryptography;

namespace Murmur
{
    public abstract class Murmur128 : HashAlgorithm
    {
        private readonly uint _seed;

        protected Murmur128(uint seed)
        {
            this._seed = seed;
        }

        protected uint Seed
        {
            get { return this._seed; }
        }

        public override int HashSize
        {
            get { return 128; }
        }
    }
}