# MathMaze SDK

**MathMaze v1.0.0-beta1** – Experimental Novel Cryptography Library

MathMaze is an experimental cryptography library implemented in C#.  
It provides a seed-based, block encryption system with reversible chaos transformations, GF(256) arithmetic, and trapdoor key encapsulation.

> ⚠️ **Beta Version:** Use for research/testing purposes. Not recommended for production security.

---

## Features

- Seed-based encryption/decryption (`MathMazeCore`)
- Quantum-resistant trapdoor key encapsulation (`Trapdoor`)
- Reversible chaos transformations (`Chaos`)
- GF(256) arithmetic operations (`GF256`)
- Block-based encryption with CBC-like chaining
- Fully in-memory, portable C# library

---
## Quick Usage Example

```csharp
using System;
using System.Text;
using System.Numerics;
using System.Security.Cryptography;
using MathMaze.Security;

class Example
{
    static void Main()
    {
        string text = "Hello, MathMaze!";
        byte[] message = Encoding.UTF8.GetBytes(text);

        // Generate random 256-bit seed
        byte[] seedBytes = new byte[32];
        RandomNumberGenerator.Fill(seedBytes);
        BigInteger seed = new BigInteger(seedBytes, isUnsigned: true, isBigEndian: false);

        // Encrypt
        byte[] cipher = MathMazeCore.EncryptWithSeed(message, seed);

        // Decrypt
        byte[] recovered = MathMazeCore.DecryptWithSeed(cipher, seed);
        string recoveredText = Encoding.UTF8.GetString(recovered);

        Console.WriteLine(recoveredText); // Output: "Hello, MathMaze!"
    }
}


## Installation via NuGet

```bash
dotnet add package MathMaze --version 1.0.0-beta1
