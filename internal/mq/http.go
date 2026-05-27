package mq

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	proto "github.com/BillShiyaoZhang/agent-comm/proto"
	goproto "google.golang.org/protobuf/proto"
)

// HTTPHandler returns an http.Handler for the MQ REST API.
func HTTPHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/mq/store", handleStore(store))
	mux.HandleFunc("GET /api/v1/mq/retrieve", handleRetrieve(store))
	mux.HandleFunc("POST /api/v1/mq/ack", handleAck(store))
	return mux
}

type storeReq struct {
	RecipientURN string `json:"recipient_urn"`
	ExpiryUnix   int64  `json:"expiry_unix"`
	// Payload is base64-encoded protobuf of EncryptedEnvelope
	PayloadProto []byte `json:"payload_proto"`
}

func handleStore(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req storeReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var env proto.EncryptedEnvelope
		if err := goproto.Unmarshal(req.PayloadProto, &env); err != nil {
			http.Error(w, "invalid payload proto", http.StatusBadRequest)
			return
		}
		id, err := store.StoreEnvelope(r.Context(), req.RecipientURN, &env, req.ExpiryUnix)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "message_id": id})
	}
}

// handleRetrieve requires Ed25519 signature authentication.
// The client must set headers:
//
//	X-URN: <recipient_urn>
//	X-Timestamp: <unix seconds>
//	X-Pubkey: <hex ed25519 pubkey>
//	X-Signature: <hex ed25519 sig over "mq-retrieve|<urn>|<timestamp big-endian 8 bytes>">
func handleRetrieve(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := r.Header.Get("X-URN")
		tsStr := r.Header.Get("X-Timestamp")
		pubkeyHex := r.Header.Get("X-Pubkey")
		sigHex := r.Header.Get("X-Signature")

		if urn == "" {
			http.Error(w, "X-URN required", http.StatusBadRequest)
			return
		}

		// Verify auth is provided and valid
		if pubkeyHex == "" || sigHex == "" || tsStr == "" {
			http.Error(w, "auth failed: signature headers (X-Pubkey, X-Signature, X-Timestamp) are required", http.StatusUnauthorized)
			return
		}

		if err := verifyRetrieveAuth(urn, tsStr, pubkeyHex, sigHex); err != nil {
			http.Error(w, "auth failed: "+err.Error(), http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		envs, ids, err := store.RetrieveEntry(ctx, urn)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		type msgItem struct {
			MessageID    string `json:"message_id"`
			PayloadProto []byte `json:"payload_proto"`
		}
		var items []msgItem
		for i, env := range envs {
			data, _ := goproto.Marshal(env)
			items = append(items, msgItem{MessageID: ids[i], PayloadProto: data})
		}
		if items == nil {
			items = []msgItem{}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"messages": items, "count": len(items)})
	}
}

type ackReq struct {
	MessageIDs []string `json:"message_ids"`
}

func handleAck(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ackReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		n, err := store.Ack(r.Context(), req.MessageIDs)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "deleted": n})
	}
}

func verifyRetrieveAuth(urn, tsStr, pubkeyHex, sigHex string) error {
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	now := time.Now().Unix()
	if now-ts > 300 || ts-now > 60 {
		return fmt.Errorf("timestamp out of window")
	}

	pubkey, err := hexDecode(pubkeyHex)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey")
	}
	sig, err := hexDecode(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex")
	}

	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(ts))
	msg := append([]byte("mq-retrieve|"+urn+"|"), tsBuf...)

	if !ed25519.Verify(ed25519.PublicKey(pubkey), msg, sig) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func hexDecode(s string) ([]byte, error) {
	n := len(s)
	if n%2 != 0 {
		return nil, fmt.Errorf("odd hex length")
	}
	b := make([]byte, n/2)
	for i := 0; i < n; i += 2 {
		hi := hexVal(s[i])
		lo := hexVal(s[i+1])
		if hi == 255 || lo == 255 {
			return nil, fmt.Errorf("invalid hex char")
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 255
}
