#!/usr/bin/env python
# coding: utf-8

# https://github.com/open-quantum-safe/liboqs-python
import oqs
import sys
from os.path import exists, join
import pathlib
from os import makedirs

# https://pycryptodome.readthedocs.io/en/latest/index.html
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa


pqsigs = oqs.get_enabled_sig_mechanisms()
nqsigs = ["Ed25519", "Ed448"]


def SIGN(sigalg, key_name, file_name, sig_name = ""):
    """
    SIGN creates a signature file for a signed document
    sigalg: signature algorithm to use
    key_name: name/location of the signer's secret key
    file_name: name/location of the documet to sign
    sig_name: name/location of the resulting signature
    """
    
    # Open the key file (note: key is hex encoded)
    with open(key_name, "r") as secret_key:
    
        # Open the document file (binary mode)
        with open(file_name, "rb") as file:
        
            # Sign
            if sigalg in pqsigs:
                # With OQS
                with oqs.Signature(sigalg) as signer:
                
                    # Instantiate the signer with the (secret) key
                    signer = oqs.Signature(sigalg, bytes.fromhex(secret_key.read()))
                
                    # Sign the document
                    signature = signer.sign(file.read())
                    
            elif sigalg in nqsigs:
                # With PyCryptodome
                key = ECC.import_key(bytes.fromhex(secret_key.read()).decode())
                
                signer = eddsa.new(key, "rfc8032")
                
                signature = signer.sign(file.read())

            
    # Open and write a file with the signature (hex encoded)
    sigsavepath = "signatures"
    
    if not exists(sigsavepath):
            makedirs(sigsavepath)
 
    with open(join(sigsavepath, sig_name), "w") as file:
        file.write(signature.hex())
        print("Signature successfully created!")


def VERIFY(sigalg, key_name, file_name, sig_name):
    """
    VERIFY verifies a signed documents from its signature file
    sigalg: signature algorithm to use
    key_name: name/location of the signer's secret key
    file_name: name/location of the documet to sign
    sig_name: name/location of the signature
    """
    
    # Open the document file (binary mode)
    with open(file_name, "rb") as file:
        
        # Open the signature file (note: sig is hex encoded)
        with open(sig_name, "r") as sig:
            
            # Open the key file (note: key is hex encoded)
            with open(key_name, "r") as public_key:
                
                # Verify
                if sigalg in pqsigs:
                    # With OQS
                    with oqs.Signature(sigalg) as verifier:
                    
                        try:
                            if verifier.verify(file.read(), bytes.fromhex(sig.read()), bytes.fromhex(public_key.read())):
                                print("Verification: Passed!")
                            else:
                                print("Verification: Failed!")
                        except:
                            print("Verification: Failed!")
                            
                elif sigalg in nqsigs:
                    # With PyCryptodome
                    key = ECC.import_key(bytes.fromhex(public_key.read()).decode())
                    
                    verifier = eddsa.new(key, "rfc8032")
                    
                    try:
                        if verifier.verify(file.read(), bytes.fromhex(sig.read())):
                            print("Verification: Passed!")
                        else:
                            print("Verification: Passed!")
                    except:
                        print("Verification: Failed!")
                            

def KEYS(sigalg, user_name = ""):
    """
    KEYS generates a (public, secret) key pair
    sigalg: signature algorithm to use
    user_name: name to prepend to the generated key pair
    """
    
    keysavepath = "keys"
    if not exists(keysavepath):
        makedirs(keysavepath)

    # Add a underscore to the user name
    if user_name != "":
        user_name = user_name + "_"
    
    # Generate a (public, secret) key pair
    if sigalg in pqsigs:
        # With OQS
        with oqs.Signature(sigalg) as signer:
            public_key = signer.generate_keypair()
            secret_key = signer.export_secret_key()
    elif sigalg in nqsigs:
        # With PyCryptodome
        key = ECC.generate(curve = sigalg)
        secret_key = key.export_key(format = "PEM").encode()
        public_key = key.public_key().export_key(format = "PEM").encode()
        
    # Open and write a file with the public key (hex encoded)
    with open(join(keysavepath, user_name + "public.key"), "w") as file:
        file.write(public_key.hex())
        print("Public key saved as: " + user_name + "public.key")
    
    # Open and write a file with the secret key (hex encoded)
    with open(join(keysavepath, user_name + "secret.key"), "w") as file:
        file.write(secret_key.hex())          
        print("Secret key saved as: " + user_name + "secret.key")
        
                            
def INTER():
    
    # Initialize the variables
    mode = ""
    sigalg = ""
    key = ""
    file = ""
    sig = ""
    user_name = ""
    
    while mode not in ("0", "1", "2", "3", "4", "5"):
        print("Available modes:")
        print("1. Sign a document")
        print("2. Verify a document")
        print("3. Generate Key pair")
        print("4. List Post-Quantum Signature algorithms")
        print("5. List Non-Quantum Signature algorithms")
        print("0. Quit")
        mode = input("Enter mode (0, 1, 2, 3, 4, 5): ")
        
    if mode == "0":
        sys.exit()

    if mode != "4" and mode != "5":
        while sigalg == "":
            sigalg = input("Select signing algorithm (default: Dilithium5): ")
    
            if sigalg == "":
                sigalg = "Dilithium5"
            elif sigalg not in pqsigs and sigalg not in nqsigs:
                print("Algorithm not recognized!")
                sigalg = ""
    
    if mode == "3":
        user_name = input("Enter user name: ")
        KEYS(sigalg, user_name)
        return
    
    elif mode == "4":
        print("Enabled Post-Quantum signature mechanisms: ")
        print(pqsigs)
        return
    
    elif mode == "5":
        print("Enabled classical signature mechanisms: ")
        print(nqsigs)
        return
    
    elif mode == "1":
        while key == "":
            key = input("Enter secret key name/location: ")
            
            if not exists(key) and key != "":
                
                if pathlib.Path(key).suffix != ".key":
                    key = join("keys", key + ".key")
                else:
                    key = join("keys", key)
                
                if not exists(key):
                    print("Secret key does not exist!")
                    key = ""
                
    elif mode == "2":
        while key == "":
            key = input("Enter public key name/location: ")
            
            if not exists(key) and key != "":
                
                if pathlib.Path(key).suffix != ".key":
                    key = join("keys", key + ".key")
                else:
                    key = join("keys", key)
                
                if not exists(key):
                    print("Public key does not exist!")
                    key = ""
    
    while file == "":
        file = input("Enter document name/location: ")
        if not exists(file):
            print("Document does not exist!")
            file = ""
    
    while sig == "":
        sig = input("Enter signature name/location: ")
        
        if mode == "2":
            if not exists(sig) and sig != "":
                
                if pathlib.Path(sig).suffix != ".sig":
                    sig = join("signatures", sig + ".sig")
                else:
                    sig = join("signatures", sig)
                
                if not exists(sig):
                    print("Signature does not exist!")
                    sig = ""
                    
        elif mode == "1":
            if sig == "":
                sig = pathlib.Path(file).stem + ".sig"
            elif pathlib.Path(sig).suffix != ".sig":
                sig = sig + ".sig"
 
    # Call the corresponding function
    if mode == "1":
        SIGN(sigalg, key, file, sig)
    elif mode == "2":
        VERIFY(sigalg, key, file, sig)
    

def main(argv):
    while True:
        INTER()
        

if __name__ == "__main__":
    main(sys.argv[1:])
