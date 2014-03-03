using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq.Expressions;
using System.Reflection;
using System.Security.Cryptography;

namespace Jither.PBKDF2
{
    /// <summary>
    /// Generic implementation allowing any HMAC type to be used as PRF. We're using Reflection here to
    /// instantiate the HMAC, which, as mentioned below is likely premature optimization AND total overkill.
    /// 
    /// A simpler implementation for a single HMAC may be found in HMACSHA512PseudoRandomFunction.
    /// </summary>
    /// <typeparam name="T">The HMAC to use as the PRF.</typeparam>
    public sealed class HMACPseudoRandomFunction<T> : HMACPseudoRandomFunction where T : HMAC
    {
        public HMACPseudoRandomFunction(byte[] input)
            : base(typeof(T), input)
        {
        }
    }

    public abstract class HMACPseudoRandomFunction : IPseudoRandomFunction
    {
        private static readonly Dictionary<Type, Func<byte[], HMAC>> constructors = new Dictionary<Type, Func<byte[], HMAC>>();

        private HMAC hmac;
        private bool disposed;

        protected HMACPseudoRandomFunction(Type hmacType, byte[] input)
        {
            var constructor = GetConstructor(hmacType);
            hmac = constructor(input);
        }

        // May be premature optimization and total overkill, but whatever - rather than using Activator.CreateInstance,
        // we create a compiled constructor lambda and cache it by type. We could let the caller do the instantiation
        // of the HMAC, passing it into the PRF constructor, but right now, today, I prefer giving this class complete
        // ownership (instantiation and disposal).
        protected Func<byte[], HMAC> GetConstructor(Type type)
        {
            Func<byte[], HMAC> result;
            if (!constructors.TryGetValue(type, out result))
            {
                ConstructorInfo cstr = type.GetConstructor(new[] { typeof(byte[]) });
                Debug.Assert(cstr != null, "HMAC-derived type doesn't have a constructor(byte[] input)");
                var argExpr = Expression.Parameter(typeof(byte[]));
                var newExpr = Expression.New(cstr, argExpr);
                var lambda = Expression.Lambda<Func<byte[], HMAC>>(newExpr, argExpr);
                result = lambda.Compile();
                constructors.Add(type, result);
            }
            return result;
        }

        public int HashSize
        {
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
