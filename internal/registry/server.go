package registry

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
)

const ProtoID = "/hermes/agent-comm/registry/1.0.0"

type streamRegisterReq struct {
	URN          string   `json:"urn"`
	PeerID       string   `json:"peer_id"`
	Addrs        []string `json:"addrs"`
	X25519Pubkey []byte   `json:"x25519_pubkey"`
	Ed25519Pubkey []byte  `json:"ed25519_pubkey"`
	Signature    []byte   `json:"signature"`
	Timestamp    int64    `json:"timestamp"`
	Op           string   `json:"op"` // "register" | "resolve"
}

type streamResp struct {
	Ok           bool     `json:"ok"`
	Found        bool     `json:"found"`
	Info         string   `json:"info,omitempty"`
	PeerID       string   `json:"peer_id,omitempty"`
	Addrs        []string `json:"addrs,omitempty"`
	X25519Pubkey []byte   `json:"x25519_pubkey,omitempty"`
}

// Server handles URN registration and resolution via libp2p streams (JSON framing).
type Server struct {
	host  host.Host
	store *Store
}

func NewServer(h host.Host, store *Store) *Server {
	s := &Server{host: h, store: store}
	h.SetStreamHandler(protocol.ID(ProtoID), s.handleStream)
	return s
}

func (s *Server) handleStream(stream network.Stream) {
	defer stream.Close()
	buf, err := io.ReadAll(stream)
	if err != nil || len(buf) == 0 {
		return
	}
	var req streamRegisterReq
	if err := json.Unmarshal(buf, &req); err != nil {
		fmt.Fprintf(stream, `{"ok":false,"info":"bad request"}`)
		return
	}
	var resp streamResp
	switch req.Op {
	case "register":
		err := s.store.Register(req.URN, req.PeerID, req.Addrs, nil,
			req.X25519Pubkey, req.Ed25519Pubkey, req.Signature, req.Timestamp)
		resp.Ok = err == nil
		if err != nil {
			resp.Info = err.Error()
		}
	case "resolve":
		entry, err := s.store.Resolve(req.URN)
		if err != nil || entry == nil {
			resp.Found = false
		} else {
			resp.Found = true
			resp.PeerID = entry.PeerID
			resp.Addrs = entry.Addrs
			resp.X25519Pubkey = entry.X25519Pubkey
		}
	default:
		resp.Info = "unknown op"
	}
	out, _ := json.Marshal(resp)
	stream.Write(out)
}
