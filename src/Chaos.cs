namespace MathMaze.Security
{
    /// <summary>
    /// Provides a simple chaos-based transformation for bytes.
    /// Supports forward and backward transformations using a seed and iteration count.
    /// </summary>
    public static class Chaos
    {
        /// <summary>
        /// Multiplication constant used in the forward transformation.
        /// </summary>
        private const int MULT = 5;

        /// <summary>
        /// Multiplicative inverse constant used in the backward transformation.
        /// </summary>
        private const int INV = 205;

        /// <summary>
        /// Applies the forward chaos transformation on a byte value.
        /// </summary>
        /// <param name="val">The byte value to transform.</param>
        /// <param name="seed">The seed value influencing the transformation.</param>
        /// <param name="iter">Number of iterations to apply.</param>
        /// <returns>The transformed byte.</returns>
        public static byte Forward(byte val, byte seed, int iter)
        {
            for (int i = 0; i < iter; i++)
                val = (byte)((((val ^ seed) * MULT) + seed) & 0xFF);
            return val;
        }

        /// <summary>
        /// Reverses the forward chaos transformation on a byte value.
        /// </summary>
        /// <param name="val">The transformed byte value to reverse.</param>
        /// <param name="seed">The seed value used in the original forward transformation.</param>
        /// <param name="iter">Number of iterations used in the forward transformation.</param>
        /// <returns>The original byte before transformation.</returns>
        public static byte Backward(byte val, byte seed, int iter)
        {
            for (int i = 0; i < iter; i++)
            {
                int tmp = (val - seed) & 0xFF;
                tmp = (tmp * INV) & 0xFF;
                val = (byte)(tmp ^ seed);
            }
            return val;
        }
    }
}
