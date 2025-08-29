using System;

namespace MathMaze.Security
{
    /// <summary>
    /// Provides finite field arithmetic over GF(2^8), used in cryptography.
    /// Supports multiplication and multiplicative inverse operations.
    /// </summary>
    public static class GF256
    {
        /// <summary>
        /// Multiplies two bytes in GF(2^8) using the Rijndael (AES) polynomial.
        /// </summary>
        /// <param name="a">First byte operand.</param>
        /// <param name="b">Second byte operand.</param>
        /// <returns>The product of the two bytes in GF(2^8).</returns>
        public static byte Mul(byte a, byte b)
        {
            byte result = 0;
            for (int i = 0; i < 8; i++)
            {
                if ((b & 1) != 0) result ^= a;
                bool hi = (a & 0x80) != 0;
                a <<= 1;
                if (hi) a ^= 0x1B;
                b >>= 1;
            }
            return result;
        }

        /// <summary>
        /// Computes the multiplicative inverse of a byte in GF(2^8).
        /// </summary>
        /// <param name="a">The byte to invert. Cannot be zero.</param>
        /// <returns>The multiplicative inverse of the byte.</returns>
        /// <exception cref="ArgumentException">Thrown if the input is zero.</exception>
        public static byte Inv(byte a)
        {
            if (a == 0) throw new ArgumentException("No inverse for zero");
            byte res = 1;
            for (int i = 0; i < 254; i++)
                res = Mul(res, a);
            return res;
        }
    }
}
