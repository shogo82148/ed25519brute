package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"sync"

	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ssh"
)

const ChildEnvName = "BRUTE_SSH_KEY_CHILD"
const TotalEnvName = "BRUTE_SSH_KEY_TOTAL"

var (
	aKey    []byte = []byte("a")
	aKeyLen int    = 1

	target = []byte("AAAAC3NzaC1lZDI1NTE5AAAAIBVji5kBXa8PbDP1nk+nysVA89VMg27z98D4aVT/j4Fa")
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

func bruteAuthorizedKey(idx, total int) ed25519.PrivateKey {
	for i, j := idx, 0; i < 1<<32; i, j = i+total, j+1 {
		fastRandReader := &fastRandReaderImpl{rand.New(rand.NewSource(int64(i)))}
		var seed [ed25519.SeedSize]byte
		var encodedPublicKey [encodedPublicKeyLen]byte
		for {
			privateKey := generateKey(fastRandReader, seed)

			// the process itself is the same as the end of ssh.MarshalAuthorizedKeys.
			// the public key is included after the private key, so encode it with a shift of 1 character to consider
			// padding.
			base64.StdEncoding.Encode(encodedPublicKey[:], privateKey[32-1:])

			if bytes.Equal(encodedPublicKey[encodedPublicKeyLen-aKeyLen:], aKey) {
				if j%1024 == 0 {
					log.Printf("%08x %s", i, string(encodedPublicKey[:]))
				}
				if bytes.Equal(encodedPublicKey[2:], target[len(target)-encodedPublicKeyLen+2:]) {
					return privateKey
				}
				break
			}
		}
	}
	return nil
}

func childProcess() {
	idx, err := strconv.Atoi(os.Getenv(ChildEnvName))
	if err != nil {
		panic(err)
	}
	total, err := strconv.Atoi(os.Getenv(TotalEnvName))
	if err != nil {
		panic(err)
	}
	privateKey := bruteAuthorizedKey(idx, total)
	if privateKey == nil {
		return
	}

	pemBlock, _ := pemutil.SerializeOpenSSHPrivateKey(privateKey)
	pem.Encode(os.Stdout, pemBlock)
}

func child(ctx context.Context, privateKeyChan chan<- ed25519.PrivateKey, i int, total int) {
	cmd := exec.CommandContext(ctx, os.Args[0], os.Args[1:]...)
	cmd.Env = append(
		os.Environ(),
		fmt.Sprintf("%s=%d", ChildEnvName, i),
		fmt.Sprintf("%s=%d", TotalEnvName, total),
	)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return
	}

	privateKey, err := pemutil.ParseOpenSSHPrivateKey(buf.Bytes())
	if err != nil {
		panic(err)
	}
	privateKeyChan <- privateKey.(ed25519.PrivateKey)
}

func main() {
	if os.Getenv(ChildEnvName) != "" {
		childProcess()
		return
	}

	log.Println("start")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	privateKeyChan := make(chan ed25519.PrivateKey, runtime.NumCPU())
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			child(ctx, privateKeyChan, i, runtime.NumCPU())
		}()
	}

	privateKey := <-privateKeyChan
	cancel()
	wg.Wait()

	log.Println("found")

	pemBlock, _ := pemutil.SerializeOpenSSHPrivateKey(privateKey)
	privateKeyPem := pem.EncodeToMemory(pemBlock)
	signer, _ := ssh.NewSignerFromSigner(privateKey)
	authorizedKey := ssh.MarshalAuthorizedKey(signer.PublicKey())

	_ = os.WriteFile("out", privateKeyPem, 0600)
	_ = os.WriteFile("out.pub", authorizedKey, 0644)
}
