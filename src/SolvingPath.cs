using System.Collections.Generic;

namespace MathMaze.Security
{
    /// <summary>
    /// Represents a solving path for the MathMaze cryptography system.
    /// Stores the layers, permutations, keys, shifts, and other parameters used in encryption/decryption.
    /// </summary>
    public class SolvingPath
    {
        /// <summary>
        /// Gets or sets the number of layers in the solving path.
        /// </summary>
        public int Layers { get; set; }

        /// <summary>
        /// Gets or sets the permutations for each layer.
        /// Each inner list represents a permutation of indices for a layer.
        /// </summary>
        public List<List<int>> Permutations { get; set; } = new();

        /// <summary>
        /// Gets or sets the XOR keys used for each layer.
        /// </summary>
        public List<List<byte>> XorKeys { get; set; } = new();

        /// <summary>
        /// Gets or sets the shift values for each layer.
        /// </summary>
        public List<List<int>> Shifts { get; set; } = new();

        /// <summary>
        /// Gets or sets the chaos seeds used for each layer.
        /// </summary>
        public List<List<byte>> ChaosSeeds { get; set; } = new();

        /// <summary>
        /// Gets or sets the Galois Field multipliers for each layer.
        /// </summary>
        public List<List<byte>> GfMultipliers { get; set; } = new();

        /// <summary>
        /// Gets or sets the S-boxes for each layer.
        /// </summary>
        public List<List<byte>> SBoxes { get; set; } = new();
    }
}
