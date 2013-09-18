#pragma warning disable 1587
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
using System.Runtime.CompilerServices;

// ReSharper disable CheckNamespace
namespace Murmur
// ReSharper restore CheckNamespace
{
    internal class Murmur128ManagedX86 : Murmur128
    {
        private const uint _c1 = 0x239b961bU;

        private const uint _c2 = 0xab0e9789U;

        private const uint _c3 = 0x38b34ae5U;

        private const uint _c4 = 0xa1e38b93U;

        internal Murmur128ManagedX86(uint seed = 0)
            : base(seed)
        {
            this.Reset();
        }

        private uint H1
        {
            get;
            set;
        }

        private uint H2
        {
            get;
            set;
        }

        private uint H3
        {
            get;
            set;
        }

        private uint H4
        {
            get;
            set;
        }

        private int Length
        {
            get;
            set;
        }

        private void Reset()
        {
            // initialize hash values to seed values
            this.H1 = this.H2 = this.H3 = this.H4 = this.Seed;
            this.Length = 0;
        }

        public override void Initialize()
        {
            this.Reset();
        }

        protected override void HashCore(byte[] array, int ibStart, int cbSize)
        {
            // store the length of the hash (for use later)
            this.Length += cbSize;
            this.Body(array, ibStart, cbSize);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Body(byte[] data, int start, int length)
        {
            int remainder = length & 15;
            int alignedLength = start + (length - remainder);
            for (int i = start; i < alignedLength; i += 16)
            {
                uint k1 = data.ToUInt32(i),
                     k2 = data.ToUInt32(i + 4),
                     k3 = data.ToUInt32(i + 8),
                     k4 = data.ToUInt32(i + 12);

                this.H1 ^= (k1*_c1).RotateLeft(15)*_c2;
                this.H1 = (this.H1.RotateLeft(19) + this.H2)*5 + 0x561ccd1b;

                this.H2 ^= (k2*_c2).RotateLeft(16)*_c3;
                this.H2 = (this.H2.RotateLeft(17) + this.H3)*5 + 0x0bcaa747;

                this.H3 ^= (k3*_c3).RotateLeft(17)*_c4;
                this.H3 = (this.H3.RotateLeft(15) + this.H4)*5 + 0x96cd1c35;

                this.H4 ^= (k4*_c4).RotateLeft(18)*_c1;
                this.H4 = (this.H4.RotateLeft(13) + this.H1)*5 + 0x32ac3b17;
            }

            if (remainder > 0)
                this.Tail(data, alignedLength, remainder);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void Tail(byte[] tail, int position, int remainder)
        {
            // create our keys and initialize to 0
            uint k1 = 0, k2 = 0, k3 = 0, k4 = 0;

            // determine how many bytes we have left to work with based on length
            switch (remainder)
            {
                case 15:
                    k4 ^= (uint) tail[position + 14] << 16;
                    goto case 14;
                case 14:
                    k4 ^= (uint) tail[position + 13] << 8;
                    goto case 13;
                case 13:
                    k4 ^= (uint) tail[position + 12] << 0;
                    goto case 12;
                case 12:
                    k3 ^= (uint) tail[position + 11] << 24;
                    goto case 11;
                case 11:
                    k3 ^= (uint) tail[position + 10] << 16;
                    goto case 10;
                case 10:
                    k3 ^= (uint) tail[position + 9] << 8;
                    goto case 9;
                case 9:
                    k3 ^= (uint) tail[position + 8] << 0;
                    goto case 8;
                case 8:
                    k2 ^= (uint) tail[position + 7] << 24;
                    goto case 7;
                case 7:
                    k2 ^= (uint) tail[position + 6] << 16;
                    goto case 6;
                case 6:
                    k2 ^= (uint) tail[position + 5] << 8;
                    goto case 5;
                case 5:
                    k2 ^= (uint) tail[position + 4] << 0;
                    goto case 4;
                case 4:
                    k1 ^= (uint) tail[position + 3] << 24;
                    goto case 3;
                case 3:
                    k1 ^= (uint) tail[position + 2] << 16;
                    goto case 2;
                case 2:
                    k1 ^= (uint) tail[position + 1] << 8;
                    goto case 1;
                case 1:
                    k1 ^= (uint) tail[position] << 0;
                    break;
            }

            this.H4 ^= (k4*_c4).RotateLeft(18)*_c1;
            this.H3 ^= (k3*_c3).RotateLeft(17)*_c4;
            this.H2 ^= (k2*_c2).RotateLeft(16)*_c3;
            this.H1 ^= (k1*_c1).RotateLeft(15)*_c2;
        }

        protected override byte[] HashFinal()
        {
            uint len = (uint) this.Length;
            this.H1 ^= len;
            this.H2 ^= len;
            this.H3 ^= len;
            this.H4 ^= len;

            this.H1 += (this.H2 + this.H3 + this.H4);
            this.H2 += this.H1;
            this.H3 += this.H1;
            this.H4 += this.H1;

            this.H1 = this.H1.FMix();
            this.H2 = this.H2.FMix();
            this.H3 = this.H3.FMix();
            this.H4 = this.H4.FMix();

            this.H1 += (this.H2 + this.H3 + this.H4);
            this.H2 += this.H1;
            this.H3 += this.H1;
            this.H4 += this.H1;

            var result = new byte[16];
            Array.Copy(BitConverter.GetBytes(this.H1), 0, result, 0, 4);
            Array.Copy(BitConverter.GetBytes(this.H2), 0, result, 4, 4);
            Array.Copy(BitConverter.GetBytes(this.H3), 0, result, 8, 4);
            Array.Copy(BitConverter.GetBytes(this.H4), 0, result, 12, 4);

            return result;
        }
    }
}