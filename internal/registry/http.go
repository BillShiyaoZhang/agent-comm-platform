package registry

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// HTTPHandler returns an http.Handler for the Registry REST API.
func HTTPHandler(store *Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/registry/register", handleRegister(store))
	mux.HandleFunc("GET /api/v1/registry/resolve", handleResolve(store))
	mux.HandleFunc("GET /api/v1/registry/list", handleList(store))
	return mux
}

type registerReq struct {
	URN          string   `json:"urn"`
	PeerID       string   `json:"peer_id"`
	Addrs        []string `json:"addrs"`
	RelayAddrs   []string `json:"relay_addrs"`
	X25519Pubkey []byte   `json:"x25519_pubkey"` // base64 via JSON
	Ed25519Pubkey []byte  `json:"ed25519_pubkey"`
	Signature    []byte   `json:"signature"`
	Timestamp    int64    `json:"timestamp"`
}

func handleRegister(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Timestamp == 0 {
			req.Timestamp = time.Now().Unix()
		}
		if err := store.Register(req.URN, req.PeerID, req.Addrs, req.RelayAddrs,
			req.X25519Pubkey, req.Ed25519Pubkey, req.Signature, req.Timestamp); err != nil {
			http.Error(w, "register failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	}
}

func handleResolve(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		urn := r.URL.Query().Get("urn")
		if urn == "" {
			http.Error(w, "urn required", http.StatusBadRequest)
			return
		}
		entry, err := store.Resolve(urn)
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
			"found":         true,
			"urn":           entry.URN,
			"peer_id":       entry.PeerID,
			"addrs":         entry.Addrs,
			"relay_addrs":   entry.RelayAddrs,
			"x25519_pubkey": entry.X25519Pubkey,
			"expires_at":    strconv.FormatInt(entry.ExpiresAt, 10),
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
