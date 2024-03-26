package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"io"
	"log"
	"math/rand"
	"os"
	"runtime"

	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

var (
	aKey    []byte = []byte("a")
	aKeyLen int    = 1

	target []byte = []byte("AAAAC3NzaC1lZDI1NTE5AAAAIBVji5kBXa8PbDP1nk+nysVA89VMg27z98D4aVT/j4Fa")
)

const (
	// this should be base64.StdEncoding.EncodedLen(32+1).
	encodedPublicKeyLen = 44
)

type fastRandReaderImpl struct {
	*rand.Rand
}

// reduce allocation for seed rather than calling ed25519.GenerateKey directly.
func generateKey(rand io.Reader, seed [ed25519.SeedSize]byte) ed25519.PrivateKey {
	_, _ = io.ReadFull(rand, seed[:])
	return ed25519.NewKeyFromSeed(seed[:])
}

func bruteAuthorizedKey(privateKeyChan chan<- ed25519.PrivateKey, idx, total int) {
	for i := idx; i < 1<<32; i += total {
		fastRandReader := &fastRandReaderImpl{rand.New(rand.NewSource(rand.Int63()))}
		var seed [ed25519.SeedSize]byte
		var encodedPublicKey [encodedPublicKeyLen]byte
		for {
			privateKey := generateKey(fastRandReader, seed)

			// the process itself is the same as the end of ssh.MarshalAuthorizedKeys.
			// the public key is included after the private key, so encode it with a shift of 1 character to consider
			// padding.
			base64.StdEncoding.Encode(encodedPublicKey[:], privateKey[32-1:])

			if bytes.Equal(encodedPublicKey[encodedPublicKeyLen-aKeyLen:], aKey) {
				if i%2048 == 0 {
					log.Printf("%08x %s", i, string(encodedPublicKey[:]))
				}
				if bytes.Equal(encodedPublicKey[2:], target[len(target)-encodedPublicKeyLen+2:]) {
					privateKeyChan <- privateKey
				}
				break
			}
		}
	}
}

func main() {
	log.Println("start")

	privateKeyChan := make(chan ed25519.PrivateKey)
	for i := 0; i < runtime.NumCPU(); i++ {
		go bruteAuthorizedKey(privateKeyChan, i, runtime.NumCPU())
	}

	privateKey := <-privateKeyChan

	log.Println("found")

	pemBlock, _ := pemutil.SerializeOpenSSHPrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(pemBlock)
	signer, _ := ssh.NewSignerFromSigner(privateKey)
	authorizedKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	_ = os.WriteFile("out", privateKeyPem, 0600)
	_ = os.WriteFile("out.pub", authorizedKey, 0644)
}
