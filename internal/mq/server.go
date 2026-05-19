package mq

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	pb "github.com/BillShiyaoZhang/agent-comm-platform/proto"
	goproto "google.golang.org/protobuf/proto"
)

const ProtoID = "/hermes/agent-comm/mq/1.0.0"

type streamReq struct {
	Op           string   `json:"op"` // "store" | "retrieve" | "ack"
	RecipientURN string   `json:"recipient_urn,omitempty"`
	ExpiryUnix   int64    `json:"expiry_unix,omitempty"`
	MessageIDs   []string `json:"message_ids,omitempty"`
	// PayloadProto is the protobuf-encoded EncryptedEnvelope
	PayloadProto []byte `json:"payload_proto,omitempty"`
}

type streamResp struct {
	Ok           bool     `json:"ok"`
	Error        string   `json:"error,omitempty"`
	MessageID    string   `json:"message_id,omitempty"`
	DeletedCount int64    `json:"deleted_count,omitempty"`
	Payloads     [][]byte `json:"payloads,omitempty"` // each is protobuf-encoded EncryptedEnvelope
}

// StreamServer handles MQ requests over libp2p streams using JSON framing.
type StreamServer struct{ store *Store }

func NewStreamServer(h host.Host, store *Store) *StreamServer {
	s := &StreamServer{store: store}
	h.SetStreamHandler(ProtoID, s.handleStream)
	return s
}

func (s *StreamServer) handleStream(stream network.Stream) {
	defer stream.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	buf, err := io.ReadAll(stream)
	if err != nil || len(buf) == 0 {
		return
	}
	var req streamReq
	if err := json.Unmarshal(buf, &req); err != nil {
		writeJSON(stream, streamResp{Error: "bad request"})
		return
	}

	switch req.Op {
	case "store":
		var env pb.EncryptedEnvelope
		if err := goproto.Unmarshal(req.PayloadProto, &env); err != nil {
			writeJSON(stream, streamResp{Error: "bad payload"})
			return
		}
		id, err := s.store.StoreEnvelope(ctx, req.RecipientURN, &env, req.ExpiryUnix)
		if err != nil {
			writeJSON(stream, streamResp{Error: err.Error()})
		} else {
			writeJSON(stream, streamResp{Ok: true, MessageID: id})
		}
	case "retrieve":
		envs, _, err := s.store.Retrieve(ctx, req.RecipientURN)
		if err != nil {
			writeJSON(stream, streamResp{Error: err.Error()})
			return
		}
		var payloads [][]byte
		for _, env := range envs {
			data, _ := goproto.Marshal(env)
			payloads = append(payloads, data)
		}
		writeJSON(stream, streamResp{Ok: true, Payloads: payloads})
	case "ack":
		n, err := s.store.Ack(ctx, req.MessageIDs)
		if err != nil {
			writeJSON(stream, streamResp{Error: err.Error()})
		} else {
			writeJSON(stream, streamResp{Ok: true, DeletedCount: n})
		}
	default:
		writeJSON(stream, streamResp{Error: fmt.Sprintf("unknown op: %s", req.Op)})
	}
}

func writeJSON(w io.Writer, v interface{}) {
	data, _ := json.Marshal(v)
	w.Write(data)
}
