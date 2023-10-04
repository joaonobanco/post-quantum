# Key Encapsulation Mechanism

## Overview
This work aims to explore the application of NIST[^1] selected post-quantum algorithms for standardization in the context of Public-Key Encryption(KEMs).
The following functionalities are available:
* Generate a symmetric random and unique secret key;
* Generate a public-private key pair specific to a chosen algorithm for encapsulation of the secret key;
* Encapsulate and decapsulate the secret key using the chosen algorithm;
* Encrypt or decrypt information using a shared key with 32 byte length.

[^1]: The 2022 [NIST Post-Quantum Cryptography Standardization project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization) algorithm selection consist exclusively of Kyber (excluding the "-90s" variants).

## Files Description
`KEM-AES.py` runs the functionalities mentioned in the overview.

`KEM-Timings.ipynb` outputs the times for encryption and decryption of each algorithm.

`KEM-CIRCL.go` executes a hybrid classical-postquantum KEM (Kyber512-X25519)  

## Suported Signature scheme algorithms
The list below indicates an extensive list of all Digital Signature algorithms supported by [liboqs](https://openquantumsafe.org/liboqs/algorithms/). 

+ **Classic McEliece**: Classic-McEliece-348864†, Classic-McEliece-348864f†, Classic-McEliece-460896†, Classic-McEliece-460896f†, Classic-McEliece-6688128†, Classic-McEliece-6688128f†, Classic-McEliece-6960119†, Classic-McEliece-6960119f†, Classic-McEliece-8192128†, Classic-McEliece-8192128f†;
+ **FrodoKEM**: FrodoKEM-640-AES, FrodoKEM-640-SHAKE, FrodoKEM-976-AES, FrodoKEM-976-SHAKE, FrodoKEM-1344-AES, FrodoKEM-1344-SHAKE
+ **HQC**: HQC-128, HQC-192, HQC-256†;
+ **Kyber**: Kyber512, Kyber512-90s, Kyber768, Kyber768-90s, Kyber1024, Kyber1024-90s;
+ **NTRU-Prime**: sntrup761.

>Note that for algorithms marked with a dagger (†), liboqs contains at least one implementation that uses a large amount of stack space; this may cause failures when run in threads or in constrained environments.
