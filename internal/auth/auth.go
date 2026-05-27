package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// VerifySignatureMiddleware verifies that the request payload is signed by the client's private key,
// and the signature is sent in the Authorization header.
func VerifySignatureMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, "auth failed: Authorization header is required", http.StatusUnauthorized)
			return
		}

		// Support "Ed25519 <signature-hex>:<pubkey-hex>" or fallback formats
		token := auth
		parts := strings.Split(auth, " ")
		if len(parts) == 2 {
			token = parts[1]
		} else if len(parts) > 2 {
			http.Error(w, "auth failed: invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		tokenParts := strings.Split(token, ":")
		if len(tokenParts) != 2 {
			tokenParts = strings.Split(token, ".")
			if len(tokenParts) != 2 {
				tokenParts = strings.Split(token, " ")
			}
		}
		if len(tokenParts) != 2 {
			http.Error(w, "auth failed: invalid token format, expected signature:pubkey", http.StatusUnauthorized)
			return
		}

		sigBytes, err := hex.DecodeString(tokenParts[0])
		if err != nil || len(sigBytes) != 64 {
			http.Error(w, "auth failed: invalid signature format or length", http.StatusUnauthorized)
			return
		}

		pubkeyBytes, err := hex.DecodeString(tokenParts[1])
		if err != nil || len(pubkeyBytes) != 32 {
			http.Error(w, "auth failed: invalid public key format or length", http.StatusUnauthorized)
			return
		}

		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request: failed to read body", http.StatusBadRequest)
			return
		}
		// Restore body for downstream handlers
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		if !ed25519.Verify(ed25519.PublicKey(pubkeyBytes), bodyBytes, sigBytes) {
			http.Error(w, "auth failed: signature verification failed", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// ExtractPubkeyFromAuth extracts the public key bytes from the Authorization header.
func ExtractPubkeyFromAuth(auth string) ([]byte, error) {
	if auth == "" {
		return nil, fmt.Errorf("empty auth header")
	}

	token := auth
	parts := strings.Split(auth, " ")
	if len(parts) == 2 {
		token = parts[1]
	} else if len(parts) > 2 {
		return nil, fmt.Errorf("invalid format")
	}

	tokenParts := strings.Split(token, ":")
	if len(tokenParts) != 2 {
		tokenParts = strings.Split(token, ".")
		if len(tokenParts) != 2 {
			tokenParts = strings.Split(token, " ")
		}
	}
	if len(tokenParts) != 2 {
		return nil, fmt.Errorf("invalid format")
	}

	pubkeyBytes, err := hex.DecodeString(tokenParts[1])
	if err != nil || len(pubkeyBytes) != 32 {
		return nil, fmt.Errorf("invalid pubkey")
	}
	return pubkeyBytes, nil
}
