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

using System.Runtime.CompilerServices;

// ReSharper disable CheckNamespace
namespace Murmur
// ReSharper restore CheckNamespace
{
    internal class Murmur128UnmanagedX64 : Murmur128
    {
        private const ulong _c1 = 0x87c37b91114253d5UL;

        private const ulong _c2 = 0x4cf5ad432745937fUL;

        internal Murmur128UnmanagedX64(uint seed = 0)
            : base(seed)
        {
            this.Reset();
        }

        private ulong H1
        {
            get;
            set;
        }

        private ulong H2
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
            this.H1 = this.H2 = this.Seed;
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
                    ulong* current = (ulong*) d;

                    while (blocks-- > 0)
                    {
                        // a variant of original algorithm optimized for processor instruction pipelining
                        this.H1 ^= (*current++*_c1).RotateLeft(31)*_c2;
                        this.H1 = (this.H1.RotateLeft(27) + this.H2)*5 + 0x52dce729;

                        this.H2 ^= (*current++*_c2).RotateLeft(33)*_c1;
                        this.H2 = (this.H2.RotateLeft(31) + this.H1)*5 + 0x38495ab5;
                    }

                    if (remainder > 0)
                        this.Tail(d + (length - remainder), remainder);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe void Tail(byte* tail, int remaining)
        {
            // create our keys and initialize to 0
            ulong k1 = 0, k2 = 0;

            // determine how many bytes we have left to work with based on length
            switch (remaining)
            {
                case 15:
                    k2 ^= (ulong) tail[14] << 48;
                    goto case 14;
                case 14:
                    k2 ^= (ulong) tail[13] << 40;
                    goto case 13;
                case 13:
                    k2 ^= (ulong) tail[12] << 32;
                    goto case 12;
                case 12:
                    k2 ^= (ulong) tail[11] << 24;
                    goto case 11;
                case 11:
                    k2 ^= (ulong) tail[10] << 16;
                    goto case 10;
                case 10:
                    k2 ^= (ulong) tail[9] << 8;
                    goto case 9;
                case 9:
                    k2 ^= (ulong) tail[8] << 0;
                    goto case 8;
                case 8:
                    k1 ^= (ulong) tail[7] << 56;
                    goto case 7;
                case 7:
                    k1 ^= (ulong) tail[6] << 48;
                    goto case 6;
                case 6:
                    k1 ^= (ulong) tail[5] << 40;
                    goto case 5;
                case 5:
                    k1 ^= (ulong) tail[4] << 32;
                    goto case 4;
                case 4:
                    k1 ^= (ulong) tail[3] << 24;
                    goto case 3;
                case 3:
                    k1 ^= (ulong) tail[2] << 16;
                    goto case 2;
                case 2:
                    k1 ^= (ulong) tail[1] << 8;
                    goto case 1;
                case 1:
                    k1 ^= (ulong) tail[0] << 0;
                    break;
            }

            this.H2 ^= (k2*_c2).RotateLeft(33)*_c1;
            this.H1 ^= (k1*_c1).RotateLeft(31)*_c2;
        }

        protected override byte[] HashFinal()
        {
            ulong len = (ulong) this.Length;
            this.H1 ^= len;
            this.H2 ^= len;

            this.H1 += this.H2;
            this.H2 += this.H1;

            this.H1 = this.H1.FMix();
            this.H2 = this.H2.FMix();

            this.H1 += this.H2;
            this.H2 += this.H1;

            var result = new byte[16];
            unsafe
            {
                fixed (byte* h = result)
                {
                    ulong* r = (ulong*) h;

                    r[0] = this.H1;
                    r[1] = this.H2;
                }
            }

            return result;
        }
    }
}