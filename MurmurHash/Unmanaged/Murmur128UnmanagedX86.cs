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

using System.Runtime.CompilerServices;

namespace Murmur
{
    internal class Murmur128UnmanagedX86 : Murmur128
    {
        private const uint C1 = 0x239b961b;

        private const uint C2 = 0xab0e9789;

        private const uint C3 = 0x38b34ae5;

        private const uint C4 = 0xa1e38b93;

        internal Murmur128UnmanagedX86(uint seed = 0)
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
            int blocks = length/16;

            unsafe
            {
                fixed (byte* d = &data[start])
                {
                    // grab a reference to blocks
                    uint* b = (uint*) d;
                    while (blocks-- > 0)
                    {
                        // K1 - consume first integer
                        this.H1 ^= (*b++*C1).RotateLeft(15)*C2;
                        this.H1 = (this.H1.RotateLeft(19) + this.H2)*5 + 0x561ccd1b;

                        // K2 - consume second integer
                        this.H2 ^= (*b++*C2).RotateLeft(16)*C3;
                        this.H2 = (this.H2.RotateLeft(17) + this.H3)*5 + 0x0bcaa747;

                        // K3 - consume third integer
                        this.H3 ^= (*b++*C3).RotateLeft(17)*C4;
                        this.H3 = (this.H3.RotateLeft(15) + this.H4)*5 + 0x96cd1c35;

                        // K4 - consume fourth integer
                        this.H4 ^= (*b++*C4).RotateLeft(18)*C1;
                        this.H4 = (this.H4.RotateLeft(13) + this.H1)*5 + 0x32ac3b17;
                    }

                    if (remainder > 0)
                        this.Tail(d + (length - remainder), remainder);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void Tail(byte* tail, int remainder)
        {
            // create our keys and initialize to 0
            uint k1 = 0, k2 = 0, k3 = 0, k4 = 0;

            // determine how many bytes we have left to work with based on length
            switch (remainder)
            {
                case 15:
                    k4 ^= (uint) tail[14] << 16;
                    goto case 14;
                case 14:
                    k4 ^= (uint) tail[13] << 8;
                    goto case 13;
                case 13:
                    k4 ^= (uint) tail[12] << 0;
                    goto case 12;
                case 12:
                    k3 ^= (uint) tail[11] << 24;
                    goto case 11;
                case 11:
                    k3 ^= (uint) tail[10] << 16;
                    goto case 10;
                case 10:
                    k3 ^= (uint) tail[9] << 8;
                    goto case 9;
                case 9:
                    k3 ^= (uint) tail[8] << 0;
                    goto case 8;
                case 8:
                    k2 ^= (uint) tail[7] << 24;
                    goto case 7;
                case 7:
                    k2 ^= (uint) tail[6] << 16;
                    goto case 6;
                case 6:
                    k2 ^= (uint) tail[5] << 8;
                    goto case 5;
                case 5:
                    k2 ^= (uint) tail[4] << 0;
                    goto case 4;
                case 4:
                    k1 ^= (uint) tail[3] << 24;
                    goto case 3;
                case 3:
                    k1 ^= (uint) tail[2] << 16;
                    goto case 2;
                case 2:
                    k1 ^= (uint) tail[1] << 8;
                    goto case 1;
                case 1:
                    k1 ^= (uint) tail[0] << 0;
                    break;
            }

            this.H4 ^= (k4*C4).RotateLeft(18)*C1;
            this.H3 ^= (k3*C3).RotateLeft(17)*C4;
            this.H2 ^= (k2*C2).RotateLeft(16)*C3;
            this.H1 ^= (k1*C1).RotateLeft(15)*C2;
        }

        protected override byte[] HashFinal()
        {
            uint len = (uint) this.Length;
            // pipelining friendly algorithm
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
            unsafe
            {
                fixed (byte* h = result)
                {
                    var r = (uint*) h;

                    r[0] = this.H1;
                    r[1] = this.H2;
                    r[2] = this.H3;
                    r[3] = this.H4;
                }
            }

            return result;
        }
    }
}