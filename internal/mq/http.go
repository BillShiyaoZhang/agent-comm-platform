package mq

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	"net/http"
	"strconv"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/auth"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	proto "github.com/BillShiyaoZhang/agent-comm/proto"
	goproto "google.golang.org/protobuf/proto"
)

// HTTPHandler returns an http.Handler for the MQ REST API.
func HTTPHandler(store *Store, isStoreAllowed func() bool, isForwardAllowed func(recipientURN string) bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/mq/store", auth.VerifySignatureMiddleware(handleStore(store, isStoreAllowed, isForwardAllowed)))
	mux.HandleFunc("GET /api/v1/mq/retrieve", handleRetrieve(store))
	mux.HandleFunc("GET /api/v1/mq/subscribe", handleSubscribe(store))
	mux.HandleFunc("POST /api/v1/mq/ack", auth.VerifySignatureMiddleware(handleAck(store)))
	return mux
}

type storeReq struct {
	RecipientURN string `json:"recipient_urn"`
	ExpiryUnix   int64  `json:"expiry_unix"`
	// Payload is base64-encoded protobuf of EncryptedEnvelope
	PayloadProto []byte `json:"payload_proto"`
}

func handleStore(store *Store, isStoreAllowed func() bool, isForwardAllowed func(recipientURN string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if isStoreAllowed != nil && !isStoreAllowed() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Bad Request: message queue storage is disabled on this platform",
			})
			return
		}

		var req storeReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if isForwardAllowed != nil && !isForwardAllowed(req.RecipientURN) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Forbidden: sending messages to storage platforms is disabled by security policy",
			})
			return
		}

		var env proto.EncryptedEnvelope
		if err := goproto.Unmarshal(req.PayloadProto, &env); err != nil {
			http.Error(w, "invalid payload proto", http.StatusBadRequest)
			return
		}

		// Extract public key from Authorization header
		authPubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "store failed: invalid authorization header", http.StatusUnauthorized)
			return
		}

		// Derive URN and verify it matches the envelope's SenderUrn
		if !crypto.URNMatchesPublicKey(env.SenderUrn, authPubkey) {
			http.Error(w, "store failed: sender URN mismatch with signing key", http.StatusUnauthorized)
			return
		}

		if err := crypto.VerifyEnvelope(&env, req.RecipientURN); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		id, err := store.StoreEnvelope(coremq.WithAuthenticatedPublicKey(r.Context(), authPubkey), req.RecipientURN, &env, req.ExpiryUnix)
		if err != nil {
			if errors.Is(err, ErrInvalidMessage) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if errors.Is(err, ErrQueueFull) {
				w.Header().Set("Retry-After", "5")
				http.Error(w, err.Error(), http.StatusTooManyRequests)
				return
			}
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

		publicKey, _ := hexDecode(pubkeyHex)
		ctx, cancel := context.WithTimeout(coremq.WithAuthenticatedPublicKey(r.Context(), publicKey), 10*time.Second)
		defer cancel()

		envs, ids, err := store.RetrieveEntry(ctx, urn)
		if err != nil {
			if errors.Is(err, ErrInvalidMessage) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
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
	RecipientURN string   `json:"recipient_urn"`
	Timestamp    int64    `json:"timestamp"`
	MessageIDs   []string `json:"message_ids"`
}

func handleAck(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ackReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		publicKey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !crypto.URNMatchesPublicKey(req.RecipientURN, publicKey) {
			http.Error(w, "ack failed: recipient does not match signing key", http.StatusUnauthorized)
			return
		}
		if err := verifyTimestamp(req.Timestamp); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), publicKey)
		n, err := store.Ack(ctx, req.RecipientURN, req.MessageIDs)
		if err != nil {
			if errors.Is(err, ErrInvalidMessage) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "deleted": n})
	}
}

func verifyRetrieveAuth(urn, tsStr, pubkeyHex, sigHex string) error {
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp")
	}
	if err := verifyTimestamp(ts); err != nil {
		return err
	}
	pubkey, err := hexDecode(pubkeyHex)
	if err != nil || len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid pubkey")
	}
	if !crypto.URNMatchesPublicKey(urn, pubkey) {
		return fmt.Errorf("recipient URN mismatch with signing key")
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

func verifyTimestamp(ts int64) error {
	now := time.Now().Unix()
	if ts < now-300 || ts > now+60 {
		return fmt.Errorf("timestamp out of window")
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

func handleSubscribe(store *Store) http.HandlerFunc {
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

		// Support Server-Sent Events headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		// Create subscriber channel
		ch := make(chan *proto.EncryptedEnvelope, 4)
		publicKey, _ := hexDecode(pubkeyHex)
		if err := store.RegisterSubscriber(coremq.WithAuthenticatedPublicKey(r.Context(), publicKey), urn, ch); err != nil {
			if errors.Is(err, ErrSubscriberLimit) {
				w.Header().Set("Retry-After", "5")
				http.Error(w, err.Error(), http.StatusTooManyRequests)
				return
			}
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		defer store.UnregisterSubscriber(urn, ch)

		// Create a flusher so we can push data immediately
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		// Send initial keepalive comment to open the stream
		_, _ = fmt.Fprint(w, ": ok\n\n")
		flusher.Flush()

		// Heartbeat ticker to prevent proxy timeouts
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case env := <-ch:
				payloadBytes, err := goproto.Marshal(env)
				if err != nil {
					continue
				}
				// Format as SSE data line
				type msgItem struct {
					MessageID    string `json:"message_id"`
					PayloadProto []byte `json:"payload_proto"`
				}
				data, err := json.Marshal(msgItem{
					MessageID:    env.GetMessageId(),
					PayloadProto: payloadBytes,
				})
				if err != nil {
					continue
				}
				_, err = fmt.Fprintf(w, "data: %s\n\n", string(data))
				if err != nil {
					return // connection closed or errored
				}
				flusher.Flush()
			case <-ticker.C:
				// Send ping to keep connection alive
				_, err := fmt.Fprint(w, ": keepalive\n\n")
				if err != nil {
					return
				}
				flusher.Flush()
			}
		}
	}
}
