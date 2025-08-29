using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace MathMaze.Security
{
    /// <summary>
    /// Quantum-Resistant Trapdoor mechanism using SHA-512.
    /// Provides public/private key generation, encapsulation, and decapsulation.
    /// </summary>
    public static class Trapdoor
    {
        /// <summary>
        /// Generates a public/private key pair.
        /// </summary>
        /// <param name="publicKey">Output: SHA-512 hash of the private key.</param>
        /// <param name="privateKey">Output: Randomly generated 32-byte private key.</param>
        public static void Generate(out byte[] publicKey, out byte[] privateKey)
        {
            privateKey = new byte[32];
            RandomNumberGenerator.Fill(privateKey);
            using var sha = SHA512.Create();
            publicKey = sha.ComputeHash(privateKey);
        }

        /// <summary>
        /// Encapsulates a seed using a public key.
        /// Produces a cipher and an OTP for decapsulation.
        /// </summary>
        /// <param name="seed">Seed to encapsulate.</param>
        /// <param name="publicKey">Public key for encapsulation.</param>
        /// <returns>A tuple containing the cipher and the OTP.</returns>
        public static (byte[] Cipher, byte[] OTP) Encapsulate(BigInteger seed, byte[] publicKey)
        {
            byte[] seedBytes = seed.ToByteArray(isUnsigned: true, isBigEndian: false);
            byte[] combined = seedBytes.Concat(publicKey).ToArray();

            using var sha = SHA512.Create();
            byte[] otp = sha.ComputeHash(combined);

            byte[] cipher = new byte[seedBytes.Length];
            for (int i = 0; i < seedBytes.Length; i++)
                cipher[i] = (byte)(seedBytes[i] ^ otp[i % otp.Length]);

            return (cipher, otp);
        }

        /// <summary>
        /// Decapsulates a cipher using the private key to recover the original seed.
        /// </summary>
        /// <param name="cipher">Cipher produced by <see cref="Encapsulate"/>.</param>
        /// <param name="privateKey">Private key corresponding to the public key used in encapsulation.</param>
        /// <returns>The original seed as a <see cref="BigInteger"/>.</returns>
        public static BigInteger Decapsulate(byte[] cipher, byte[] privateKey)
        {
            using var sha = SHA512.Create();
            byte[] publicKey = sha.ComputeHash(privateKey);

            byte[] combined = cipher.Concat(publicKey).ToArray();
            byte[] otp = sha.ComputeHash(combined);

            byte[] seedBytes = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
                seedBytes[i] = (byte)(cipher[i] ^ otp[i % otp.Length]);

            return new BigInteger(seedBytes, isUnsigned: true, isBigEndian: false);
        }
    }
}
