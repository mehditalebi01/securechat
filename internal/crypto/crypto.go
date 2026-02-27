package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	"golang.org/x/crypto/curve25519"
)

// Generate X25519 keypair
func GenerateKeyPair() (priv, pub []byte) {
	priv = make([]byte, 32)
	rand.Read(priv)
	pub, _ = curve25519.X25519(priv, curve25519.Basepoint)
	return
}

// X25519 DH
func DH(priv, pub []byte) []byte {
	shared, _ := curve25519.X25519(priv, pub)
	return shared
}

// HKDF-SHA256
func HKDF(secret []byte, info string) []byte {
	h := hkdf.New(sha256.New, secret, nil, []byte(info))
	out := make([]byte, 32)
	io.ReadFull(h, out)
	return out
}

// AES-GCM encrypt
func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce = make([]byte, gcm.NonceSize())
	rand.Read(nonce)
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return
}

// AES-GCM decrypt
func Decrypt(key, nonce, ciphertext []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	plaintext, _ := gcm.Open(nil, nonce, ciphertext, nil)
	return plaintext
}
