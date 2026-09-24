package mq

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/BillShiyaoZhang/agent-comm-platform/internal/auth"
	"github.com/BillShiyaoZhang/agent-comm/crypto"
	coremq "github.com/BillShiyaoZhang/agent-comm/mq"
	"github.com/BillShiyaoZhang/agent-comm/v2"
)

// V2HTTPHandler exposes a different protocol namespace from the protobuf v1
// endpoints. Every store route validates against the same signed policy.
func V2HTTPHandler(store *Store, gateway *V2Gateway) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v2/policy", func(w http.ResponseWriter, r *http.Request) {
		policy := DescribeV2Policy(r.Context(), store, gateway)
		if policy == nil {
			http.Error(w, "signed policy unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("ETag", `"`+policy.PolicyHash+`"`)
		writeV2JSON(w, map[string]any{"policy": gateway.RawPolicy})
	})
	mux.HandleFunc("POST /api/v2/mq/store", auth.VerifySignatureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RecipientURN string `json:"recipient_urn"`
			ExpiryUnix   int64  `json:"expiry_unix"`
			Envelope     []byte `json:"envelope"`
		}
		if err := decodeV2Body(r, &req); err != nil {
			http.Error(w, "invalid v2 request", http.StatusBadRequest)
			return
		}
		pubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "invalid sender authorization", http.StatusUnauthorized)
			return
		}
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), pubkey)
		id, receipt, err := gateway.AdmitV2(ctx, store, ed25519.PublicKey(pubkey), req.RecipientURN, req.Envelope, req.ExpiryUnix)
		if err != nil {
			writeV2StoreError(w, err)
			return
		}
		writeV2JSON(w, map[string]any{"ok": true, "message_id": id, "receipt": receipt})
	}))
	mux.HandleFunc("GET /api/v2/mq/retrieve", func(w http.ResponseWriter, r *http.Request) {
		pubkey, urn, ok := v2RetrieveAuth(w, r)
		if !ok {
			return
		}
		ctx, cancel := context.WithTimeout(coremq.WithAuthenticatedPublicKey(r.Context(), pubkey), 10*time.Second)
		defer cancel()
		messages, err := store.RetrieveV2(ctx, urn)
		if err != nil {
			http.Error(w, "retrieve failed", http.StatusInternalServerError)
			return
		}
		type item struct {
			MessageID string `json:"message_id"`
			Envelope  []byte `json:"envelope"`
			Receipt   []byte `json:"receipt"`
		}
		out := make([]item, 0, len(messages))
		for _, msg := range messages {
			out = append(out, item{msg.ID, msg.Envelope, msg.Receipt})
		}
		writeV2JSON(w, map[string]any{"messages": out, "count": len(out)})
	})
	mux.HandleFunc("POST /api/v2/mq/ack", auth.VerifySignatureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req ackReq
		if err := decodeV2Body(r, &req); err != nil {
			http.Error(w, "invalid v2 ACK", http.StatusBadRequest)
			return
		}
		pubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !crypto.URNMatchesPublicKey(req.RecipientURN, pubkey) || verifyTimestamp(req.Timestamp) != nil {
			http.Error(w, "invalid recipient authorization", http.StatusUnauthorized)
			return
		}
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), pubkey)
		n, err := store.AckV2(ctx, req.RecipientURN, req.MessageIDs)
		if err != nil {
			http.Error(w, "ACK failed", http.StatusBadRequest)
			return
		}
		writeV2JSON(w, map[string]any{"ok": true, "deleted": n})
	}))
	mux.HandleFunc("POST /api/v2/handshake/store", auth.VerifySignatureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Frame []byte `json:"frame"`
		}
		if err := decodeV2Body(r, &req); err != nil {
			http.Error(w, "invalid frame request", http.StatusBadRequest)
			return
		}
		frame, err := v2.ParseFrame(req.Frame)
		if err != nil {
			http.Error(w, "invalid frame", http.StatusBadRequest)
			return
		}
		pubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !crypto.URNMatchesPublicKey(frame.SenderURN, pubkey) {
			http.Error(w, "invalid sender authorization", http.StatusUnauthorized)
			return
		}
		if err := gateway.CheckCurrent(); err != nil {
			http.Error(w, "signed policy unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := v2.VerifyFrame(frame, ed25519.PublicKey(pubkey)); err != nil {
			http.Error(w, "invalid frame signature", http.StatusBadRequest)
			return
		}
		if err := v2.ValidateFrameForRelay(gateway.Policy, frame, time.Now()); err != nil {
			http.Error(w, "invalid handshake payload", http.StatusBadRequest)
			return
		}
		id := v2.FrameHash(frame)
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), pubkey)
		expiry := time.Now().Add(24 * time.Hour).Unix()
		if expiry > gateway.Policy.ExpiresAt {
			expiry = gateway.Policy.ExpiresAt
		}
		switch frame.Type {
		case v2.FrameInit:
			var payload v2.InitPayload
			if err := json.Unmarshal(frame.Payload, &payload); err != nil {
				http.Error(w, "invalid init payload", http.StatusBadRequest)
				return
			}
			if expiry > payload.Expiry {
				expiry = payload.Expiry
			}
		case v2.FrameAccept:
			var payload v2.AcceptPayload
			if err := json.Unmarshal(frame.Payload, &payload); err != nil {
				http.Error(w, "invalid accept payload", http.StatusBadRequest)
				return
			}
			if expiry > payload.Expiry {
				expiry = payload.Expiry
			}
		}
		if err := store.StoreV2Frame(ctx, frame.SenderURN, frame.RecipientURN, id, req.Frame, expiry, gateway.Policy, ed25519.PublicKey(pubkey)); err != nil {
			writeV2StoreError(w, err)
			return
		}
		writeV2JSON(w, map[string]any{"ok": true, "frame_id": id})
	}))
	mux.HandleFunc("POST /api/v2/handshake/retrieve", auth.VerifySignatureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RecipientURN string `json:"recipient_urn"`
			Limit        int    `json:"limit"`
		}
		if err := decodeV2Body(r, &req); err != nil || req.Limit < 0 || req.Limit > 100 {
			http.Error(w, "invalid frame retrieve", http.StatusBadRequest)
			return
		}
		pubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !crypto.URNMatchesPublicKey(req.RecipientURN, pubkey) {
			http.Error(w, "invalid recipient authorization", http.StatusUnauthorized)
			return
		}
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), pubkey)
		frames, err := store.RetrieveV2Frames(ctx, req.RecipientURN)
		if err != nil {
			http.Error(w, "frame retrieve failed", http.StatusInternalServerError)
			return
		}
		if req.Limit > 0 && len(frames) > req.Limit {
			frames = frames[:req.Limit]
		}
		type item struct {
			FrameID string `json:"frame_id"`
			Frame   []byte `json:"frame"`
		}
		out := make([]item, 0, len(frames))
		for _, f := range frames {
			out = append(out, item{f.ID, f.Frame})
		}
		writeV2JSON(w, map[string]any{"frames": out, "count": len(out)})
	}))
	mux.HandleFunc("POST /api/v2/handshake/ack", auth.VerifySignatureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RecipientURN string   `json:"recipient_urn"`
			FrameIDs     []string `json:"frame_ids"`
		}
		if err := decodeV2Body(r, &req); err != nil {
			http.Error(w, "invalid frame ACK", http.StatusBadRequest)
			return
		}
		pubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !crypto.URNMatchesPublicKey(req.RecipientURN, pubkey) {
			http.Error(w, "invalid recipient authorization", http.StatusUnauthorized)
			return
		}
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), pubkey)
		n, err := store.AckV2Frames(ctx, req.RecipientURN, req.FrameIDs)
		if err != nil {
			http.Error(w, "frame ACK failed", http.StatusBadRequest)
			return
		}
		writeV2JSON(w, map[string]any{"ok": true, "deleted": n})
	}))
	mux.HandleFunc("POST /api/v2/managed/identity", auth.VerifySignatureMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Certificate []byte `json:"certificate"`
		}
		if err := decodeV2Body(r, &req); err != nil {
			http.Error(w, "invalid managed enrollment", http.StatusBadRequest)
			return
		}
		cert, err := v2.ParseManagedCertificate(req.Certificate)
		if err != nil {
			http.Error(w, "invalid certificate", http.StatusBadRequest)
			return
		}
		pubkey, err := auth.ExtractPubkeyFromAuth(r.Header.Get("Authorization"))
		if err != nil || !bytes.Equal(pubkey, cert.IdentityPublicKey) {
			http.Error(w, "console key possession required", http.StatusUnauthorized)
			return
		}
		if err := gateway.CheckCurrent(); err != nil {
			http.Error(w, "signed policy unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := v2.VerifyManagedCertificate(cert, gateway.Policy, time.Now()); err != nil {
			http.Error(w, "invalid managed certificate", http.StatusBadRequest)
			return
		}
		ctx := coremq.WithAuthenticatedPublicKey(r.Context(), pubkey)
		if err := store.EnrollManaged(ctx, gateway.Policy, req.Certificate); err != nil {
			writeV2StoreError(w, err)
			return
		}
		writeV2JSON(w, map[string]any{"ok": true, "urn": cert.URN, "expires_at": cert.ExpiresAt})
	}))
	mux.HandleFunc("POST /api/v2/managed/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req managedRevocation
		if err := decodeV2Body(r, &req); err != nil {
			http.Error(w, "invalid revocation", http.StatusBadRequest)
			return
		}
		if err := gateway.CheckCurrent(); err != nil {
			http.Error(w, "signed policy unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.PlatformID != gateway.Policy.PlatformID {
			http.Error(w, "wrong platform", http.StatusBadRequest)
			return
		}
		if err := verifyManagedRevocation(&req, gateway.Policy.ManagedIssuerPublicKey); err != nil {
			http.Error(w, "invalid issuer signature", http.StatusUnauthorized)
			return
		}
		if err := store.RevokeManaged(r.Context(), req.Serial); err != nil {
			writeV2StoreError(w, err)
			return
		}
		writeV2JSON(w, map[string]any{"ok": true})
	})
	return mux
}

func decodeV2Body(r *http.Request, value any) error {
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	if err != nil {
		return err
	}
	if len(raw) > (2 << 20) {
		return errors.New("v2 body exceeds limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func writeV2JSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func writeV2StoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrQueueFull):
		w.Header().Set("Retry-After", "5")
		http.Error(w, err.Error(), http.StatusTooManyRequests)
	case errors.Is(err, ErrV2Policy):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrV2Conflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, ErrInvalidMessage):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, "v2 admission failed", http.StatusBadRequest)
	}
}

func v2RetrieveAuth(w http.ResponseWriter, r *http.Request) ([]byte, string, bool) {
	urn := r.Header.Get("X-URN")
	if urn == "" {
		http.Error(w, "X-URN required", http.StatusBadRequest)
		return nil, "", false
	}
	if err := verifyRetrieveAuth(urn, r.Header.Get("X-Timestamp"), r.Header.Get("X-Pubkey"), r.Header.Get("X-Signature")); err != nil {
		http.Error(w, "invalid retrieve signature", http.StatusUnauthorized)
		return nil, "", false
	}
	pubkey, err := hexDecode(r.Header.Get("X-Pubkey"))
	if err != nil {
		http.Error(w, "invalid retrieve key", http.StatusUnauthorized)
		return nil, "", false
	}
	return pubkey, urn, true
}

type managedRevocation struct {
	Version    int    `json:"version"`
	PlatformID string `json:"platform_id"`
	Serial     string `json:"serial"`
	RevokedAt  int64  `json:"revoked_at"`
	Signature  []byte `json:"signature"`
}

func verifyManagedRevocation(req *managedRevocation, issuer ed25519.PublicKey) error {
	if req == nil || req.Version != v2.Version || req.Serial == "" || len(req.Serial) > 128 || len(issuer) != ed25519.PublicKeySize || verifyTimestamp(req.RevokedAt) != nil {
		return errors.New("invalid revocation fields")
	}
	unsigned := *req
	unsigned.Signature = nil
	data, err := v2.Canonical(unsigned)
	if err != nil {
		return err
	}
	if !ed25519.Verify(issuer, append([]byte("agent-comm-v2-managed-revoke\x00"), data...), req.Signature) {
		return fmt.Errorf("invalid revocation signature")
	}
	return nil
}
