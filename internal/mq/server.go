package mq

import (
	"context"
	"io"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"

	pb "github.com/BillShiyaoZhang/agent-comm-platform/proto"
	goproto "google.golang.org/protobuf/proto"
)

const ProtoID = "/hermes/agent-comm/mq/1.0.0"

// StreamServer handles MQ requests over libp2p streams using protobuf framing.
// Matches agent-comm client: 4-byte big-endian length prefix + protobuf body.
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

	// Read 4-byte big-endian length prefix, then protobuf body
	sizeBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, sizeBuf); err != nil {
		return
	}
	size := uint32(sizeBuf[0])<<24 | uint32(sizeBuf[1])<<16 | uint32(sizeBuf[2])<<8 | uint32(sizeBuf[3])
	if size > 1<<20 { // 1MB sanity cap
		return
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(stream, data); err != nil {
		return
	}

	var req pb.MQRequest
	if err := goproto.Unmarshal(data, &req); err != nil {
		writeResp(stream, &pb.MQResponse{
			Op: &pb.MQResponse_Error{Error: &pb.ErrorResponse{Message: "bad request"}},
		})
		return
	}

	switch op := req.GetOp().(type) {
	case *pb.MQRequest_Store:
		storeReq := op.Store
		envpb := storeReq.Payload
		id, err := s.store.StoreEnvelope(ctx, storeReq.RecipientUrn, envpb, storeReq.ExpiryUnix)
		if err != nil {
			writeResp(stream, &pb.MQResponse{
				Op: &pb.MQResponse_Error{Error: &pb.ErrorResponse{Message: err.Error()}},
			})
		} else {
			writeResp(stream, &pb.MQResponse{
				Op: &pb.MQResponse_Store{Store: &pb.StoreResponse{Ok: true, MessageId: id}},
			})
		}

	case *pb.MQRequest_Retrieve:
		envs, _, err := s.store.Retrieve(ctx, op.Retrieve.RecipientUrn)
		if err != nil {
			writeResp(stream, &pb.MQResponse{
				Op: &pb.MQResponse_Error{Error: &pb.ErrorResponse{Message: err.Error()}},
			})
			return
		}
		writeResp(stream, &pb.MQResponse{
			Op: &pb.MQResponse_Retrieve{Retrieve: &pb.RetrieveResponse{Payloads: envs}},
		})

	case *pb.MQRequest_Ack:
		n, err := s.store.Ack(ctx, op.Ack.MessageIds)
		if err != nil {
			writeResp(stream, &pb.MQResponse{
				Op: &pb.MQResponse_Error{Error: &pb.ErrorResponse{Message: err.Error()}},
			})
		} else {
			writeResp(stream, &pb.MQResponse{
				Op: &pb.MQResponse_Ack{Ack: &pb.AckResponse{Ok: true, DeletedCount: int32(n)}},
			})
		}

	default:
		writeResp(stream, &pb.MQResponse{
			Op: &pb.MQResponse_Error{Error: &pb.ErrorResponse{Message: "unknown op"}},
		})
	}
}

// writeResp marshals a pb.MQResponse and writes it with 4-byte big-endian length prefix.
func writeResp(stream network.Stream, resp *pb.MQResponse) {
	data, err := goproto.Marshal(resp)
	if err != nil {
		return
	}
	sizeBuf := [4]byte{
		byte(len(data) >> 24),
		byte(len(data) >> 16),
		byte(len(data) >> 8),
		byte(len(data)),
	}
	stream.Write(sizeBuf[:])
	stream.Write(data)
}
