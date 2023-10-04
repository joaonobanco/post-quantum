package main

// Based on examples at https://github.com/cloudflare/circl/tree/master/kem/kyber

import (
	"fmt"
	"math/rand"
	"os"
	"time"

    crand "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "encoding/base64"
    
    "io"

	"github.com/cloudflare/circl/kem/schemes"
    "github.com/cloudflare/circl/dh/x25519"
)

func calculateMean(numbers []float64) float64 {
    sum := 0.0
    for _, num := range numbers {
        sum += num
    }
    return sum / float64(len(numbers))
}

func kyberx25519() (enc_time float64, dec_time float64) {

	meth := "Kyber512-X25519" // Kyber768-X448 Kyber1024-X448

	argCount := len(os.Args[1:])

	if argCount > 0 {
		meth = os.Args[1]
	}

	scheme := schemes.ByName(meth)
	rand.Seed(time.Now().Unix())


	pk, sk, _ := scheme.GenerateKeyPair()
	//ppk, _ := pk.MarshalBinary()
	//psk, _ := sk.MarshalBinary()
    
    tic := time.Now()
	ct, _, _ := scheme.Encapsulate(pk)
    enc_time = time.Since(tic).Seconds()
    
    tic = time.Now()
	_, _ = scheme.Decapsulate(sk, ct)
    dec_time = time.Since(tic).Seconds()
    
    return

	//fmt.Printf("Method: %s \n", meth)

	//fmt.Printf("Public Key (pk) = %X (first 32 bytes)\n", ppk[:32])
	//fmt.Printf("Private key (sk) = %X (first 32 bytes)\n", psk[:32])
	//fmt.Printf("Cipher text (ct) = %X (first 32 bytes)\n", ct[:32])
	//fmt.Printf("\nShared key (Bob):\t%X\n", ss)
	//fmt.Printf("Shared key (Alice):\t%X", ss2)

	//fmt.Printf("\n\nLength of Public Key (pk) = %d bytes \n", len(ppk))
	//fmt.Printf("Length of Secret Key (sk)  = %d  bytes\n", len(psk))
	//fmt.Printf("Length of Cipher text (ct) = %d  bytes\n", len(ct))

}

func kyber() (enc_time float64, dec_time float64) {

	meth := "Kyber512"

	argCount := len(os.Args[1:])

	if argCount > 0 {
		meth = os.Args[1]
	}

	scheme := schemes.ByName(meth)
	rand.Seed(time.Now().Unix())

	var seed [48]byte
	kseed := make([]byte, scheme.SeedSize())
	eseed := make([]byte, scheme.EncapsulationSeedSize())
	for i := 0; i < 48; i++ {
		seed[i] = byte(rand.Intn(255))
	}


	pk, sk := scheme.DeriveKeyPair(kseed)
	//ppk, _ := pk.MarshalBinary()
	//psk, _ := sk.MarshalBinary()
    tic := time.Now()
	ct, _, _ := scheme.EncapsulateDeterministically(pk, eseed)
    enc_time = time.Since(tic).Seconds()
    
    tic = time.Now()
	_, _ = scheme.Decapsulate(sk, ct)
    dec_time = time.Since(tic).Seconds()
    
    return

	//fmt.Printf("Method: %s \n", meth)
	//fmt.Printf("Seed for key exchange: %X\n", seed)

	//fmt.Printf("Public Key (pk) = %X (first 32 bytes)\n", ppk[:32])
	//fmt.Printf("Private key (sk) = %X (first 32 bytes)\n", psk[:32])
	//fmt.Printf("Cipher text (ct) = %X (first 32 bytes)\n", ct[:32])
	//fmt.Printf("\nShared key (Bob):\t%X\n", ss)
	//fmt.Printf("Shared key (Alice):\t%X", ss2)

	//fmt.Printf("\n\nLength of Public Key (pk) = %d bytes \n", len(ppk))
	//fmt.Printf("Length of Secret Key (pk)  = %d  bytes\n", len(psk))
	//fmt.Printf("Length of Cipher text (ct) = %d  bytes\n", len(ct))

}


func frodo() (enc_time float64, dec_time float64) {
	//fmt.Printf("FrodoKEM-640-SHAKE \n")

	scheme := schemes.ByName("FrodoKEM-640-SHAKE")

	var seed [48]byte

	kseed := make([]byte, scheme.SeedSize())

	eseed := make([]byte, scheme.EncapsulationSeedSize())

	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)

	for i := 0; i < 48; i++ {
		seed[i] = byte(r1.Intn(255))
	}

	//g := NewDRBG(&seed)

	//g.Fill(seed[:])

	//g2 := NewDRBG(&seed)

	//g2.Fill(kseed[:])

	pk, sk := scheme.DeriveKeyPair(kseed)

	//ppk, _ := pk.MarshalBinary()
	//psk, _ := sk.MarshalBinary()

	//g2.Fill(eseed)
    tic := time.Now()
    ct, _, _ := scheme.EncapsulateDeterministically(pk, eseed)
    enc_time = time.Since(tic).Seconds()

    tic = time.Now()
    _, _ = scheme.Decapsulate(sk, ct)
    dec_time = time.Since(tic).Seconds()
    
    return
    

	//fmt.Printf("Alice pk (len=%d) = %X\n", len(ppk), ppk[:128])
	//fmt.Printf("Alice sk (len=%d) = %X\n", len(psk), psk[:128])
	//fmt.Printf("Bob seed = %X\n", seed)
	//fmt.Printf("Bob creates ct (len=%d) = %X\n", len(ct), ct[:128])
	//fmt.Printf("Bob's ss (len=%d) = %X\n\n", len(ss), ss)
	//fmt.Printf("Alice's ss (len=%d)  = %X\n\n", len(ss2), ss2)

}

func CheckError(e error) {
    if e != nil {
        fmt.Println(e.Error)
    }
}

func RSA_OAEP_Encrypt(secretMessage string, key rsa.PublicKey) string {
    label := []byte("OAEP Encrypted")
    rng := crand.Reader
    ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
    CheckError(err)
    return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_OAEP_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
    ct, _ := base64.StdEncoding.DecodeString(cipherText)
    label := []byte("OAEP Encrypted")
    rng := crand.Reader
    plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
    CheckError(err)
    //fmt.Println("Plaintext:", string(plaintext))
    return string(plaintext)
}

func RSA() (enc_time float64, dec_time float64) {
    privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
    CheckError(err)
 
    publicKey := privateKey.PublicKey

    bytes := make([]byte, 32)
    _, err = crand.Read(bytes)

    secretMessage := string(bytes)
 
    tic := time.Now()
    encryptedMessage := RSA_OAEP_Encrypt(secretMessage, publicKey)
    enc_time = time.Since(tic).Seconds()
 
    tic = time.Now()
    RSA_OAEP_Decrypt(encryptedMessage, *privateKey)
    dec_time = time.Since(tic).Seconds()

    //fmt.Println("Cipher Text:", encryptedMessage)
    
    return

}

func My25519() (toc float64){

    var AliceSecret, BobSecret,
        AlicePublic, BobPublic,
        AliceShared, BobShared x25519.Key

    _, _ = io.ReadFull(crand.Reader, AliceSecret[:])
    x25519.KeyGen(&AlicePublic, &AliceSecret)

    _, _ = io.ReadFull(crand.Reader, BobSecret[:])
    x25519.KeyGen(&BobPublic, &BobSecret)
    
    
    tic := time.Now()
    _ = x25519.Shared(&AliceShared, &AliceSecret, &BobPublic)
    _ = x25519.Shared(&BobShared, &BobSecret, &AlicePublic)
    toc = time.Since(tic).Seconds()
    
    return


    //fmt.Printf("Alice Secret %x\nAlice Public %x\n\n",AliceSecret,AlicePublic)
    //fmt.Printf("Bob Secret %x\nBob Public %x\n\n",BobSecret,BobPublic)

    //fmt.Printf("\nBob Shared %x\n\nAlice Shared %x",AliceShared,BobShared)
    
}

func main() {
    
    const reps int = 3
    
    kx := [2][reps]float64{}
    k := [2][reps]float64{}
    f := [2][reps]float64{}
    r := [2][reps]float64{}
    x := [reps]float64{}
    
    for i := 0; i < reps; i++ {
        
        kx[0][i], kx[1][i] = kyberx25519()

        k[0][i], k[1][i] = kyber()
        
        f[0][i], f[1][i] = frodo()
        
        r[0][i], r[1][i] = RSA()
        
        x[i] = My25519()
    }
    
    
    fmt.Print("Kyber512-X25519", "\tEnc time:", calculateMean(kx[0][:]), "\tDec time:", calculateMean(kx[1][:]), "\n")
    fmt.Print("Kyber512", "\tEnc time:", calculateMean(k[0][:]), "\tDec time:", calculateMean(k[1][:]), "\n")
    fmt.Print("FrodoKEM-640-SHAKE", "\tEnc time:", calculateMean(f[0][:]), "\tDec time:", calculateMean(f[1][:]), "\n")
    fmt.Print("RSA-2048", "\tEnc time:", calculateMean(r[0][:]), "\tDec time:", calculateMean(r[1][:]), "\n")
    fmt.Print("Ed25519", "\tTime:", calculateMean(x[:]), "\n")

}
