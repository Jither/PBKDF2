using System.Security.Cryptography;

namespace Jither.PBKDF2
{
    /// <summary>
    /// Simple implementation of HMAC SHA512 PRF
    /// </summary>
    public class HMACSHA512PseudoRandomFunction : IPseudoRandomFunction
    {
        private HMAC hmac;
        private bool disposed;

        protected HMACSHA512PseudoRandomFunction(byte[] input)
        {
            hmac = new HMACSHA512(input);
        }

        public int HashSize
        {
            // Could just return a constant 64 here
            get { return hmac.HashSize / 8; }
        }

        public byte[] Transform(byte[] input)
        {
            return hmac.ComputeHash(input);
        }

        public void Dispose()
        {
            if (!disposed)
            {
                hmac.Dispose();
                hmac = null;
                disposed = true;
            }
        }

    }
}
