# Digital Signatures
## Overview
This work aims to apply and evaluate NIST selected post-quantum algorithms for digital signatures made available by the [Open Quantum-Safe project](https://openquantumsafe.org/).
The script `DS.py` allows a user to generate and validate a digital signature of a file (any format).

`Digital_Signature-Timings.ipynb` can be used to calculate the times of signature and verification, for any of the available algorithms.

The 2022 [NIST Post-Quantum Cryptography Standardization project](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization) algorithm selection:
+ Dilithium (excluding the *-AES* variants);
+ Falcon, and SPHINCS+ (excluding the "robust" variants).

## Suported Signature scheme algorithms
The list below indicates an extensive list of all Digital Signature algorithms supported by [liboqs](https://openquantumsafe.org/liboqs/algorithms/). 

+ **CRYSTALS-Dilithium**: Dilithium2, Dilithium3, Dilithium5, Dilithium2-AES, Dilithium3-AES, Dilithium5-AES
+ **Falcon**: Falcon-512, Falcon-1024
+ **SPHINCS+-Haraka**: SPHINCS+-Haraka-128f-robust, SPHINCS+-Haraka-128f-simple, SPHINCS+-Haraka-128s-robust, SPHINCS+-Haraka-128s-simple, SPHINCS+-Haraka-192f-robust, SPHINCS+-Haraka-192f-simple, SPHINCS+-Haraka-192s-robust, SPHINCS+-Haraka-192s-simple, SPHINCS+-Haraka-256f-robust, SPHINCS+-Haraka-256f-simple, SPHINCS+-Haraka-256s-robust, SPHINCS+-Haraka-256s-simple
+ **SPHINCS+-SHA256**: SPHINCS+-SHA256-128f-robust, SPHINCS+-SHA256-128f-simple, SPHINCS+-SHA256-128s-robust, SPHINCS+-SHA256-128s-simple, SPHINCS+-SHA256-192f-robust, SPHINCS+-SHA256-192f-simple, SPHINCS+-SHA256-192s-robust, SPHINCS+-SHA256-192s-simple, SPHINCS+-SHA256-256f-robust, SPHINCS+-SHA256-256f-simple, SPHINCS+-SHA256-256s-robust, SPHINCS+-SHA256-256s-simple
+ **SPHINCS+-SHAKE256**: SPHINCS+-SHAKE256-128f-robust, SPHINCS+-SHAKE256-128f-simple, SPHINCS+-SHAKE256-128s-robust, SPHINCS+-SHAKE256-128s-simple, SPHINCS+-SHAKE256-192f-robust, SPHINCS+-SHAKE256-192f-simple, SPHINCS+-SHAKE256-192s-robust, SPHINCS+-SHAKE256-192s-simple, SPHINCS+-SHAKE256-256f-robust, SPHINCS+-SHAKE256-256f-simple, SPHINCS+-SHAKE256-256s-robust, SPHINCS+-SHAKE256-256s-simple

## Security Limitations
At the time of this writing there haven't been any known vulnerabilities in the quantum-safe algorithms utilized in this library. Deploying post-quantum algorithms requires an extra level of caution as most of these and their software haven't been subjected to the same degree of scrutiny as the presently standard algorithms.
As research advances, the security of the supported algorithms may change rapidly, and they may become susceptible to both classical and quantum computers.
