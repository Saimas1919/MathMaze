using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace MathMaze.Security
{
    /// <summary>
    /// Core MathMaze encryption system.
    /// Provides quantum-resistant encryption and decryption using block-wise paths and a trapdoor mechanism.
    /// </summary>
    public static class MathMazeCore
    {
        private const int Layers = 4;
        private const int ChaosIter = 5;

        /// <summary>
        /// Generates deterministic pseudo-random bytes from a seed and optional context.
        /// </summary>
        private static byte[] DeterministicBytes(BigInteger seed, int length, string context = "")
        {
            using var sha = SHA256.Create();
            var outBuf = new byte[length];
            int pos = 0, counter = 0;
            var seedBytes = seed.ToByteArray(isUnsigned: true, isBigEndian: false);
            var ctxBytes = Encoding.UTF8.GetBytes(context);
            while (pos < length)
            {
                var ctrBytes = BitConverter.GetBytes(counter);
                byte[] input = seedBytes.Concat(ctxBytes).Concat(ctrBytes).ToArray();
                var hash = sha.ComputeHash(input);
                int take = Math.Min(hash.Length, length - pos);
                Array.Copy(hash, 0, outBuf, pos, take);
                pos += take;
                counter++;
            }
            return outBuf;
        }

        /// <summary>
        /// Generates the solving path for a given block.
        /// </summary>
        private static SolvingPath GeneratePath(BigInteger seed, int blockIndex, int blockSize)
        {
            var path = new SolvingPath { Layers = Layers };
            BigInteger y = seed + blockIndex;
            for (int l = 0; l < Layers; l++)
            {
                var layerSeed = y + l;
                var det = DeterministicBytes(layerSeed, blockSize * 6 + 256, "MathMazeUltraPath");

                var perm = Enumerable.Range(0, blockSize).ToList();
                for (int i = 0; i < blockSize; i++)
                {
                    int j = det[i] % blockSize;
                    (perm[i], perm[j]) = (perm[j], perm[i]);
                }
                path.Permutations.Add(perm);

                path.XorKeys.Add(det.Take(blockSize).ToList());
                path.Shifts.Add(det.Skip(blockSize).Take(blockSize).Select(b => (1 + (b % 7))).ToList());
                path.ChaosSeeds.Add(det.Skip(blockSize * 2).Take(blockSize).Select(b => b == 0 ? (byte)1 : b).ToList());
                path.GfMultipliers.Add(det.Skip(blockSize * 3).Take(blockSize).Select(b => b == 0 ? (byte)1 : b).ToList());

                var sbox = Enumerable.Range(0, 256).Select(x => (byte)x).ToArray();
                int detOffset = blockSize * 4;
                for (int i = 0; i < 256; i++)
                {
                    int j = det[detOffset + i % (det.Length - detOffset)] % 256;
                    (sbox[i], sbox[j]) = (sbox[j], sbox[i]);
                }
                path.SBoxes.Add(sbox.ToList());
            }
            return path;
        }

        /// <summary>
        /// Encrypts a single block using a solving path.
        /// </summary>
        private static byte[] EncryptBlock(byte[] block, SolvingPath path)
        {
            int n = block.Length;
            byte[] data = (byte[])block.Clone();
            for (int l = 0; l < path.Layers; l++)
            {
                var indices = path.Permutations[l];
                var xor = path.XorKeys[l];
                var shifts = path.Shifts[l];
                var chaos = path.ChaosSeeds[l];
                var mults = path.GfMultipliers[l];
                var sbox = path.SBoxes[l].ToArray();

                byte[] newData = new byte[n];
                for (int i = 0; i < n; i++)
                {
                    int idx = indices[i];
                    int val = data[idx];
                    val ^= xor[i];
                    int prev1 = i > 0 ? newData[i - 1] : 0;
                    int prev2 = i > 1 ? newData[i - 2] : 0;
                    val = (val + ((prev1 * 3 + prev2) ^ chaos[i])) & 0xFF;
                    val = GF256.Mul((byte)val, mults[i]);
                    val = sbox[val];
                    int s = shifts[i];
                    val = ((val << s) | (val >> (8 - s))) & 0xFF;
                    val = Chaos.Forward((byte)val, chaos[i], ChaosIter);
                    newData[i] = (byte)val;
                }
                data = newData;
            }
            return data;
        }

        /// <summary>
        /// Decrypts a single block using a solving path.
        /// </summary>
        private static byte[] DecryptBlock(byte[] block, SolvingPath path)
        {
            int n = block.Length;
            byte[] data = (byte[])block.Clone();
            for (int l = path.Layers - 1; l >= 0; l--)
            {
                var indices = path.Permutations[l];
                var xor = path.XorKeys[l];
                var shifts = path.Shifts[l];
                var chaos = path.ChaosSeeds[l];
                var mults = path.GfMultipliers[l];
                var sbox = path.SBoxes[l].ToArray();

                byte[] prevLayer = new byte[n];
                for (int i = 0; i < n; i++)
                {
                    int val = data[i];
                    val = Chaos.Backward((byte)val, chaos[i], ChaosIter);
                    int s = shifts[i];
                    val = ((val >> s) | (val << (8 - s))) & 0xFF;
                    val = Array.IndexOf(sbox, (byte)val);
                    val = GF256.Mul((byte)val, GF256.Inv(mults[i]));
                    int prev1 = i > 0 ? data[i - 1] : 0;
                    int prev2 = i > 1 ? data[i - 2] : 0;
                    val = (val - ((prev1 * 3 + prev2) ^ chaos[i]) + 256) % 256;
                    val ^= xor[i];
                    prevLayer[indices[i]] = (byte)val;
                }
                data = prevLayer;
            }
            return data;
        }

        /// <summary>
        /// Encrypts a message using a deterministic seed.
        /// </summary>
        public static byte[] EncryptWithSeed(byte[] message, BigInteger seed, int blockSize = 16)
        {
            int padLen = blockSize - (message.Length % blockSize);
            if (padLen == 0) padLen = blockSize;
            byte[] padded = new byte[message.Length + padLen];
            Array.Copy(message, padded, message.Length);
            for (int i = message.Length; i < padded.Length; i++) padded[i] = (byte)padLen;

            byte[] iv = new byte[blockSize];
            RandomNumberGenerator.Fill(iv);
            var outBytes = new List<byte>();
            outBytes.AddRange(iv);

            byte[] prev = iv;
            for (int b = 0; b < padded.Length / blockSize; b++)
            {
                byte[] block = new byte[blockSize];
                Array.Copy(padded, b * blockSize, block, 0, blockSize);

                byte[] xored = new byte[blockSize];
                for (int i = 0; i < blockSize; i++)
                    xored[i] = (byte)(block[i] ^ prev[i]);

                var path = GeneratePath(seed, b, blockSize);
                byte[] middle = EncryptBlock(xored, path);

                byte[] otp = DeterministicBytes(seed + b, blockSize, "MathMazeUltraOTP");
                byte[] final = new byte[blockSize];
                for (int i = 0; i < blockSize; i++)
                    final[i] = (byte)(middle[i] ^ otp[i]);

                outBytes.AddRange(final);
                prev = final;
            }
            return outBytes.ToArray();
        }

        /// <summary>
        /// Decrypts a message using a deterministic seed.
        /// </summary>
        public static byte[] DecryptWithSeed(byte[] cipher, BigInteger seed, int blockSize = 16)
        {
            byte[] iv = new byte[blockSize];
            Array.Copy(cipher, 0, iv, 0, blockSize);

            int blocks = (cipher.Length - blockSize) / blockSize;
            byte[] prev = iv;
            var plainPadded = new List<byte>();

            for (int b = 0; b < blocks; b++)
            {
                byte[] final = new byte[blockSize];
                Array.Copy(cipher, blockSize + b * blockSize, final, 0, blockSize);

                byte[] otp = DeterministicBytes(seed + b, blockSize, "MathMazeUltraOTP");
                byte[] middle = new byte[blockSize];
                for (int i = 0; i < blockSize; i++)
                    middle[i] = (byte)(final[i] ^ otp[i]);

                var path = GeneratePath(seed, b, blockSize);
                byte[] decrypted = DecryptBlock(middle, path);

                byte[] block = new byte[blockSize];
                for (int i = 0; i < blockSize; i++)
                    block[i] = (byte)(decrypted[i] ^ prev[i]);

                plainPadded.AddRange(block);
                prev = final;
            }

            int padLen = plainPadded[^1];
            if (padLen < 1 || padLen > blockSize) throw new CryptographicException("Invalid padding");
            return plainPadded.Take(plainPadded.Count - padLen).ToArray();
        }

        /// <summary>
        /// Encrypts a message for a recipient using their public key.
        /// </summary>
        public static byte[] Encrypt(byte[] message, byte[] recipientPublicKey)
        {
            BigInteger seed = new BigInteger(RandomBytes(32), isUnsigned: true, isBigEndian: false);
            var (encaps, _) = Trapdoor.Encapsulate(seed, recipientPublicKey);
            byte[] cipherWithSeed = EncryptWithSeed(message, seed);
            byte[] encLenBytes = BitConverter.GetBytes(encaps.Length);
            var outBytes = new List<byte>();
            outBytes.AddRange(encLenBytes);
            outBytes.AddRange(encaps);
            outBytes.AddRange(cipherWithSeed);
            return outBytes.ToArray();
        }

        /// <summary>
        /// Decrypts a message using the recipient's private key.
        /// </summary>
        public static byte[] Decrypt(byte[] combined, byte[] recipientPrivateKey)
        {
            int encLen = BitConverter.ToInt32(combined, 0);
            byte[] encaps = new byte[encLen];
            Array.Copy(combined, 4, encaps, 0, encLen);
            byte[] cipherWithSeed = new byte[combined.Length - 4 - encLen];
            Array.Copy(combined, 4 + encLen, cipherWithSeed, 0, cipherWithSeed.Length);
            BigInteger seed = Trapdoor.Decapsulate(encaps, recipientPrivateKey);
            return DecryptWithSeed(cipherWithSeed, seed);
        }

        /// <summary>
        /// Generates a cryptographically secure random byte array.
        /// </summary>
        private static byte[] RandomBytes(int len)
        {
            byte[] b = new byte[len];
            RandomNumberGenerator.Fill(b);
            return b;
        }
    }
}
