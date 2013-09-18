namespace Murmur.Specs
{
    internal class HashExpection
    {
        private readonly uint _Result;

        private readonly int _Bits;

        public HashExpection(int bits, uint result)
        {
            this._Bits = bits;
            this._Result = result;
        }

        public uint Result
        {
            get { return this._Result; }
        }

        public int Bits
        {
            get { return this._Bits; }
        }
    }
}