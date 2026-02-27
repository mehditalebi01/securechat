package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"securechat/internal/crypto"
	"securechat/internal/ratchet"
)

type PrekeyBundle struct {
	IdentityKey []byte `json:"identity_key"`
}

type SecureMessage struct {
	FromIdentity []byte `json:"from_identity"`
	EphemeralKey []byte `json:"ephemeral_key"`
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
}

func main() {
	// Bob identity
	fmt.Println("[BOB] Generating Bob X25519 identity keypair...")
	bobPriv, bobPub := crypto.GenerateKeyPair()

	// Upload public key
	fmt.Println("[BOB] Uploading Bob public key to server (stored in Redis as prekey:bob)...")
	bundle := PrekeyBundle{IdentityKey: bobPub}
	data, err := json.Marshal(bundle)
	if err != nil {
		fmt.Println("[BOB] Error encoding prekey bundle:", err)
		os.Exit(1)
	}
	resp, err := http.Post("http://localhost:8080/upload_prekey?user=bob",
		"application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("[BOB] Error uploading prekey bundle:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Println("[BOB] Server rejected prekey upload. Status:", resp.Status, "Body:", string(body))
		os.Exit(1)
	}

	fmt.Println("[BOB] Bob ready. Polling mailbox from server (secure_mailbox:bob in Redis)...")

	for {
		resp, err := http.Get("http://localhost:8080/fetch_secure?user=bob")
		if err != nil {
			fmt.Println("[BOB] Error fetching secure message:", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(500 * time.Millisecond)
			continue
		}

		var msg SecureMessage
		if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
			resp.Body.Close()
			time.Sleep(300 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		if len(msg.Ciphertext) == 0 {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		fmt.Println("[BOB] Received encrypted message. Deriving shared secret (X25519 DH)...")
		shared := crypto.DH(bobPriv, msg.EphemeralKey)
		fmt.Println("[BOB] Initializing ratchet and deriving message key...")
		r := ratchet.NewRatchet(shared, msg.EphemeralKey)
		msgKey := r.NextMessageKey()

		fmt.Println("[BOB] Decrypting with AES-GCM...")
		plaintext := crypto.Decrypt(msgKey, msg.Nonce, msg.Ciphertext)
		fmt.Println("[BOB] Bob received:", string(plaintext))
		break
	}
}
