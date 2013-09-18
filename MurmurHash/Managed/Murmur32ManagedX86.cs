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

using System.Runtime.CompilerServices;

// ReSharper disable CheckNamespace
namespace Murmur
// ReSharper restore CheckNamespace
{
    internal class Murmur32ManagedX86 : Murmur32
    {
        public Murmur32ManagedX86(uint seed = 0)
            : base(seed)
        {
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            this.Length += cbSize;
            this.Body(array, ibStart, cbSize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Body(byte[] data, int start, int length)
        {
            int remainder = length & 3;
            int alignedLength = start + (length - remainder);

            for (int i = start; i < alignedLength; i += 4)
                this.H1 = (((this.H1 ^ (((data.ToUInt32(i)*C1).RotateLeft(15))*C2)).RotateLeft(13))*5) + 0xe6546b64;

            if (remainder > 0)
                this.Tail(data, alignedLength, remainder);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Tail(byte[] tail, int position, int remainder)
        {
            // create our keys and initialize to 0
            uint k1 = 0;

            // determine how many bytes we have left to work with based on length
            switch (remainder)
            {
                case 3:
                    k1 ^= (uint) tail[position + 2] << 16;
                    goto case 2;
                case 2:
                    k1 ^= (uint) tail[position + 1] << 8;
                    goto case 1;
                case 1:
                    k1 ^= tail[position];
                    break;
            }

            this.H1 ^= (k1*C1).RotateLeft(15)*C2;
        }
    }
}