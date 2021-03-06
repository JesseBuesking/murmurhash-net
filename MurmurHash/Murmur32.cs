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
    public abstract class Murmur32 : HashAlgorithm
    {
        protected const uint C1 = 0xcc9e2d51;

        protected const uint C2 = 0x1b873593;

        private readonly uint _seed;

        protected Murmur32(uint seed)
        {
            this._seed = seed;
            this.Reset();
        }

        public override int HashSize
        {
            get { return 32; }
        }

        private uint Seed
        {
            get { return this._seed; }
        }

        protected uint H1
        {
            get;
            set;
        }

        protected int Length
        {
            get;
            set;
        }

        private void Reset()
        {
            this.H1 = this.Seed;
            this.Length = 0;
        }

        public override void Initialize()
        {
            this.Reset();
        }

        protected override byte[] HashFinal()
        {
            this.H1 = (this.H1 ^ (uint) this.Length).FMix();

            return BitConverter.GetBytes(this.H1);
        }
    }
}