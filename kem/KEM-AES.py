#!/usr/bin/env python
# coding: utf-8

# https://github.com/open-quantum-safe/liboqs-python
import oqs

# https://pycryptodome.readthedocs.io/en/latest/index.html
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import sys
from os.path import exists, join
from os import makedirs
import pathlib
import shutil


def ENCAPSULATE(kemalg, encaps_name, key_name):
    """
    ENCAPSULATE creates a key encapsulation
    """
    
    encapssavepath = "encapsulations"
    if not exists(encapssavepath):
        makedirs(encapssavepath)
    
     # Read public key
    with open(key_name, "r") as file:
        public_key = bytes.fromhex(file.read())   
    
    # ENCAPSULATE with OQS
    # Derive a secret encapsulation
    # ciphertext -> the encapsulation
    # shared_secret_server -> the symmetric key encapsulated
    with oqs.KeyEncapsulation(kemalg) as server:
        ciphertext, shared_secret_server = server.encap_secret(public_key)
        
    # Open and write a file with the encapsulation (hex encoded)
    with open(join(encapssavepath, encaps_name), "w") as file:
        file.write(ciphertext.hex())
        print("Encapsulation saved as: " + encaps_name)
    
    # Show the symmatric key to use
    print("Your key is:")
    print(shared_secret_server.hex())


def DECAPSULATE(kemalg, encaps_name, key_name):
    """
    DECAPSULATE opens an ecapsulation
    """
    
    # Read secret key
    with open(key_name, "r") as file:
        secret_key = bytes.fromhex(file.read())
    
    # Read encapsulation
    with open(encaps_name, "r") as file:
        encaps = bytes.fromhex(file.read())
                
    # DECAPSULATE with OQS                        
    with oqs.KeyEncapsulation(kemalg) as client:

        client = oqs.KeyEncapsulation(kemalg, secret_key)

        shared_secret_client = client.decap_secret(encaps)

    # Show the symmatric key to use
    print("Your key is:")
    print(shared_secret_client.hex())


def AESenc(plain_text, key, enc_name):
    
    # Convert to bytes
    plain_text = bytes.fromhex(plain_text)
    
    plain_text = pad(plain_text, 16)
    
    key = bytes.fromhex(key)
    
    # Random Initialization Vector
    iv = get_random_bytes(16)
    
    # AES in CBC mode
    try:
        obj = AES.new(key, AES.MODE_CBC, iv)
        enc_text = obj.encrypt(plain_text)
    except:
        print("Encryption failed!")
        return
    
    # Prepend IV to encrypted text
    out = iv + enc_text
    out = out.hex()
    
    # Write encrypted file
    with open(enc_name, "w") as file:
        file.write(out)
        print("File successfully encrypted as: " + enc_name)


def AESdec(enc_text, key, doc_name):
    
    # Convert to bytes
    enc_text = bytes.fromhex(enc_text)
    key = bytes.fromhex(key) 
    
    # IV is the first 16 bytes
    iv = enc_text[:16]
    # Encrypted text is the rest
    enc_text = enc_text[16:]
    
    # AES in CBC mode
    try:
        obj = AES.new(key, AES.MODE_CBC, iv)
        plain_text = obj.decrypt(enc_text)
        plain_text = unpad(plain_text, 16)
    except:
        print("Decryption failed!")
        return
    
    # Write decrypted file
    with open(doc_name, "wb") as file:
        file.write(plain_text)
        print("File successfully decrypted as: " + doc_name)

        
def KEYS(kemalg, user_name = ""):
    """
    KEYS generates a (public, secret) key pair
    """
    
    keysavepath = "keys"
    if not exists(keysavepath):
        makedirs(keysavepath)
        
    # Add a underscore to the user name
    if user_name != "":
        user_name = user_name + "_"
    
    # Generate a (public, secret) key pair with OQS
    with oqs.KeyEncapsulation(kemalg) as client:
        public_key = client.generate_keypair()
        secret_key = client.export_secret_key()
        
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
    key_name = ""
    encaps_name = ""
    enc_name = ""
    doc_name = ""
    key = ""
    file_name = ""
    user_name = ""
    kemalg = ""
    
    while mode not in ("0", "1", "2", "3", "4", "5", "6", "7"):
        print("Available modes:")
        print("1. Encapsulate Key")
        print("2. Decapsulate Key")
        print("3. Encrypt with AES")
        print("4. Decrypt with AES")
        print("5. Generate key pair")
        print("6. List KEM algorithms")
        print("7. Delete stored encapsulations")
        print("0. Quit")
        mode = input("Enter mode (0, 1, 2, 3, 4, 5, 6, 7): ")
        
    if mode == "0":
        sys.exit()
    
    if mode == "1" or mode == "2" or mode == "5":
        while kemalg == "":
            kemalg = input("Select KEM algorithm (default: Kyber512): ")
    
            if kemalg == "":
                kemalg = "Kyber512"
            elif kemalg not in oqs.get_enabled_KEM_mechanisms():
                print("Algorithm not recognized!")
                kemalg = ""
            
    if mode == "1":
        while encaps_name == "":
            encaps_name = input("Enter encapsulation name/location: ")
            
            if pathlib.Path(encaps_name).suffix != ".kem":
                encaps_name = join(encaps_name + ".kem")
            
        while key_name == "":
            key_name = input("Enter public key name/location: ")
            
            if not exists(key_name) and key_name != "":
                
                if pathlib.Path(key_name).suffix != ".key":
                    key_name = join("keys", key_name + ".key")
                else:
                    key_name = join("keys", key_name)
                
                if not exists(key_name):
                    print("Public key does not exist!")
                    key_name = ""
            
        ENCAPSULATE(kemalg, encaps_name, key_name)
        
    elif mode == "2":
        while encaps_name == "":
            encaps_name = input("Enter encapsulation name/location: ")
                
            if not exists(encaps_name) and encaps_name != "":
                
                if pathlib.Path(encaps_name).suffix != ".kem":
                    encaps_name = join("encapsulations", encaps_name + ".kem")
                else:
                    encaps_name = join("encapsulations", encaps_name)
                    
                if not exists(encaps_name):
                    print("Encapsulation does not exist!")
                    encaps_name = ""
            
        while key_name == "":
            key_name = input("Enter secret key name/location: ")
            
            if not exists(key_name) and key_name != "":
                
                if pathlib.Path(key_name).suffix != ".key":
                    key_name = join("keys", key_name + ".key")
                else:
                    key_name = join("keys", key_name)
                
                if not exists(key_name):
                    print("Secret key does not exist!")
                    key_name = ""           
                
        DECAPSULATE(kemalg, encaps_name, key_name)
        
    elif mode == "3":
        while file_name == "":
            file_name = input("Enter document name/location: ")
            if not exists(file_name):
                print("Document does not exist!")
                file_name = ""
                
        while enc_name == "":
            enc_name = input("Enter encrypted document name/location: ")
            
        while key == "":
            key = input("Enter AES key (hex encoded): ")
            
            try:
                key_len = len(bytes.fromhex(key))
                if not key_len == 32:
                    print("Invalid key length!")
                    key = ""
            except:
                print("Invalid key length!")
                key = ""
            
        with open(file_name, "rb") as file:
            plain_text = file.read()
            
        AESenc(plain_text.hex(), key, enc_name)
            
    elif mode == "4":
        while file_name == "":
            file_name = input("Enter encrypted document name/location: ")
            if not exists(file_name):
                print("File does not exist!")
                file_name = ""
                
        while doc_name == "":
            doc_name = input("Enter decrypted document name/location: ")
            
        while key == "":
            key = input("Enter AES key (hex encoded): ")
            
            try:
                key_len = len(bytes.fromhex(key))
                if not key_len == 32:
                    print("Invalid key length!")
                    key = ""
            except:
                print("Invalid key length!")
                key = ""           
            
        with open(file_name, "r") as file:
            plain_text = file.read()
            
        AESdec(plain_text, key, doc_name)
    
    elif mode == "5":
        user_name = input("Enter user name: ")
        KEYS(kemalg, user_name)
    
    elif mode == "6":
        print("Enabled KEM mechanisms:")
        kems = oqs.get_enabled_KEM_mechanisms()
        print(kems)
        
    elif mode == "7":
        try:
            shutil.rmtree("encapsulations")
            print("Removed encapsulations")
        except:
            print("Error removing encapsulations")
        
            

def main(argv):
    while True:
        INTER()
    

if __name__ == "__main__":
    main(sys.argv[1:])
 