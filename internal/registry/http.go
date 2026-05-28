package registry

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/auth"
)

// HTTPHandler returns an http.Handler for the Registry REST API.
func HTTPHandler(store *Store, isForwardAllowed func(urn string) bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/registry/register", auth.VerifySignatureMiddleware(handleRegister(store)))
	mux.HandleFunc("GET /api/v1/registry/resolve", handleResolve(store, isForwardAllowed))
	mux.HandleFunc("GET /api/v1/registry/list", handleList(store))
	return mux
}

type registerReq struct {
	URN            string   `json:"urn"`
	PeerID         string   `json:"peer_id"`
	Addrs          []string `json:"addrs"`
	RelayAddrs     []string `json:"relay_addrs"`
	X25519Pubkey   []byte   `json:"x25519_pubkey"` // base64 via JSON
	Ed25519Pubkey   []byte  `json:"ed25519_pubkey"`
	StoresUserData bool     `json:"stores_user_data"`
	Signature      []byte   `json:"signature"`
	Timestamp      int64    `json:"timestamp"`
}

func handleRegister(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(req.Signature) == 0 || len(req.Ed25519Pubkey) == 0 || req.Timestamp == 0 {
			http.Error(w, "register failed: signature, ed25519_pubkey, and timestamp are required", http.StatusUnauthorized)
			return
		}

		// Verify that the public key in Authorization matches req.Ed25519Pubkey
		authPubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !bytes.Equal(authPubkey, req.Ed25519Pubkey) {
			http.Error(w, "register failed: public key mismatch between Authorization header and body", http.StatusUnauthorized)
			return
		}

		if err := store.RegisterWithSignature(req.URN, req.PeerID, req.Addrs, req.RelayAddrs,
			req.X25519Pubkey, req.Ed25519Pubkey, req.Signature, req.StoresUserData, req.Timestamp); err != nil {
			http.Error(w, "register failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

func handleResolve(store *Store, isForwardAllowed func(urn string) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := r.URL.Query().Get("urn")
		if urn == "" {
			http.Error(w, "urn required", http.StatusBadRequest)
			return
		}
		if isForwardAllowed != nil && !isForwardAllowed(urn) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"found": false,
				"error": "Forbidden: forwarding to storage platforms is disabled by security policy",
			})
			return
		}
		entry, err := store.ResolveEntry(urn)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if entry == nil {
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]bool{"found": false})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"found":            true,
			"urn":              entry.URN,
			"peer_id":          entry.PeerID,
			"addrs":            entry.Addrs,
			"relay_addrs":      entry.RelayAddrs,
			"x25519_pubkey":    entry.X25519Pubkey,
			"ed25519_pubkey":   entry.Ed25519Pubkey,
			"signature":        entry.Signature,
			"timestamp":        entry.Timestamp,
			"stores_user_data": entry.StoresUserData,
			"expires_at":       strconv.FormatInt(entry.ExpiresAt, 10),
		})
	}
}

func handleList(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urns, err := store.ListURNs()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"urns": urns, "count": len(urns)})
	}
}
