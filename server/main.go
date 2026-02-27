package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()
var rdb *redis.Client

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
	rdb = redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	if err := rdb.Ping(ctx).Err(); err != nil {
		fmt.Println("[SERVER] Redis is not reachable at localhost:6379:", err)
		os.Exit(1)
	}

	http.HandleFunc("/upload_prekey", uploadPrekey)
	http.HandleFunc("/prekey", getPrekey)
	http.HandleFunc("/send_secure", sendSecure)
	http.HandleFunc("/fetch_secure", fetchSecure)

	fmt.Println("[SERVER] Running on :8080 (Redis: localhost:6379)")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("[SERVER] HTTP server stopped:", err)
		os.Exit(1)
	}
}

func uploadPrekey(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	defer r.Body.Close()
	var bundle PrekeyBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	if len(bundle.IdentityKey) != 32 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid identity_key length"))
		return
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("marshal error"))
		return
	}
	if err := rdb.Set(ctx, "prekey:"+user, data, 0).Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("redis error"))
		return
	}
	fmt.Println("[SERVER] Stored prekey bundle for", user, "(Redis key: prekey:"+user+")")
	w.Write([]byte("OK"))
}

func getPrekey(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	val, err := rdb.Get(ctx, "prekey:"+user).Result()
	if err != nil {
		fmt.Println("[SERVER] Prekey not found for", user, "(Redis key: prekey:"+user+")")
		w.WriteHeader(404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(val))
	fmt.Println("[SERVER] Served prekey bundle for", user)
}

func sendSecure(w http.ResponseWriter, r *http.Request) {
	to := r.URL.Query().Get("to")
	defer r.Body.Close()
	var msg SecureMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid JSON"))
		return
	}
	if len(msg.Ciphertext) == 0 || len(msg.Nonce) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("missing fields"))
		return
	}
	data, err := json.Marshal(msg)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("marshal error"))
		return
	}
	if err := rdb.LPush(ctx, "secure_mailbox:"+to, data).Err(); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("redis error"))
		return
	}
	fmt.Println("[SERVER] Queued secure message for", to, "(Redis list: secure_mailbox:"+to+")")
	w.Write([]byte("OK"))
}

func fetchSecure(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	val, err := rdb.RPop(ctx, "secure_mailbox:"+user).Result()
	if err == redis.Nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("redis error"))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(val))
	fmt.Println("[SERVER] Delivered 1 secure message to", user)
}
