namespace Murmur.Specs
{
    internal class HashExpection
    {
        private readonly uint _result;

        private readonly int _bits;

        public HashExpection(int bits, uint result)
        {
            this._bits = bits;
            this._result = result;
        }

        public uint Result
        {
            get { return this._result; }
        }

        public int Bits
        {
            get { return this._bits; }
        }
    }
}