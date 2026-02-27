package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

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
	message, err := readMessage()
	if err != nil {
		fmt.Println("[ALICE] Error reading message:", err)
		os.Exit(1)
	}

	// Fetch Bob prekey
	fmt.Println("[ALICE] Fetching Bob prekey from server...")
	resp, err := http.Get("http://localhost:8080/prekey?user=bob")
	if err != nil {
		fmt.Println("[ALICE] Error fetching prekey:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println("[ALICE] Server did not return Bob prekey. Status:", resp.Status)
		fmt.Println("[ALICE] Run `go run ./bob` first to upload Bob's key.")
		os.Exit(1)
	}
	var bundle PrekeyBundle
	if err := json.NewDecoder(resp.Body).Decode(&bundle); err != nil {
		fmt.Println("[ALICE] Error decoding prekey bundle:", err)
		os.Exit(1)
	}
	if len(bundle.IdentityKey) != 32 {
		fmt.Println("[ALICE] Invalid Bob identity key length:", len(bundle.IdentityKey))
		os.Exit(1)
	}
	fmt.Println("[ALICE] Bob prekey received.")

	// Alice ephemeral key
	fmt.Println("[ALICE] Generating Alice ephemeral X25519 keypair...")
	alicePriv, alicePub := crypto.GenerateKeyPair()

	fmt.Println("[ALICE] Computing shared secret (X25519 DH)...")
	shared := crypto.DH(alicePriv, bundle.IdentityKey)
	fmt.Println("[ALICE] Initializing ratchet and deriving message key...")
	r := ratchet.NewRatchet(shared, bundle.IdentityKey)
	msgKey := r.NextMessageKey()

	fmt.Println("[ALICE] Encrypting message with AES-GCM...")
	nonce, ciphertext := crypto.Encrypt(msgKey, []byte(message))

	msg := SecureMessage{
		FromIdentity: alicePub,
		EphemeralKey: alicePub,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
	}

	fmt.Println("[ALICE] Sending encrypted message to server (queued for bob in Redis)...")
	data, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("[ALICE] Error encoding secure message:", err)
		os.Exit(1)
	}
	sendResp, err := http.Post("http://localhost:8080/send_secure?to=bob",
		"application/json", bytes.NewBuffer(data))
	if err != nil {
		fmt.Println("[ALICE] Error sending secure message:", err)
		os.Exit(1)
	}
	defer sendResp.Body.Close()
	if sendResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(sendResp.Body)
		fmt.Println("[ALICE] Server rejected message. Status:", sendResp.Status, "Body:", string(body))
		os.Exit(1)
	}

	fmt.Println("[ALICE] Done. Message sent.")
}

func readMessage() (string, error) {
	if len(os.Args) > 1 {
		msg := strings.TrimSpace(strings.Join(os.Args[1:], " "))
		if msg == "" {
			return "", errors.New("message is empty")
		}
		fmt.Println("[ALICE] Message from CLI args:", msg)
		return msg, nil
	}

	fmt.Print("[ALICE] Type a message to Bob and press Enter: ")
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	msg := strings.TrimSpace(line)
	if msg == "" {
		return "", errors.New("message is empty")
	}
	return msg, nil
}
