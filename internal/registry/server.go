package registry

import (
	"io"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"

	pb "github.com/BillShiyaoZhang/agent-comm-platform/proto"
	goproto "google.golang.org/protobuf/proto"
)

const ProtoID = "/hermes/agent-comm/registry/1.0.0"

// Server handles URN registration and resolution via libp2p streams.
// Uses raw protobuf framing to match agent-comm client.
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

	var req pb.URNRegistryRequest
	if err := goproto.Unmarshal(buf, &req); err != nil {
		writeResp(stream, &pb.URNRegistryResponse{
			Op: &pb.URNRegistryResponse_Register{
				Register: &pb.RegisterResponse{
					Ok:   false,
					Info: "bad request",
				},
			},
		})
		return
	}

	switch op := req.GetOp().(type) {
	case *pb.URNRegistryRequest_Register:
		regReq := op.Register
		err := s.store.Register(
			regReq.Urn,
			regReq.PeerId,
			regReq.Addrs,
			nil, // relayAddrs — not in agent-comm client proto
			regReq.X25519Pubkey,
			nil, // ed25519Pubkey — not in agent-comm client proto
			nil, // signature    — not in agent-comm client proto
			0,   // timestamp    — not in agent-comm client proto
		)
		writeResp(stream, &pb.URNRegistryResponse{
			Op: &pb.URNRegistryResponse_Register{
				Register: &pb.RegisterResponse{
					Ok:   err == nil,
					Info: func() string { if err != nil { return err.Error() }; return "" }(),
				},
			},
		})

	case *pb.URNRegistryRequest_Resolve:
		entry, err := s.store.Resolve(op.Resolve.Urn)
		if err != nil || entry == nil {
			writeResp(stream, &pb.URNRegistryResponse{
				Op: &pb.URNRegistryResponse_Resolve{
					Resolve: &pb.ResolveResponse{Found: false},
				},
			})
			return
		}

		// Validate peer.ID is well-formed
		if _, err := peer.Decode(entry.PeerID); err != nil {
			writeResp(stream, &pb.URNRegistryResponse{
				Op: &pb.URNRegistryResponse_Resolve{
					Resolve: &pb.ResolveResponse{Found: false},
				},
			})
			return
		}

		writeResp(stream, &pb.URNRegistryResponse{
			Op: &pb.URNRegistryResponse_Resolve{
				Resolve: &pb.ResolveResponse{
					Found:        true,
					PeerId:       entry.PeerID,
					Addrs:        entry.Addrs,
					X25519Pubkey: entry.X25519Pubkey,
				},
			},
		})

	default:
		writeResp(stream, &pb.URNRegistryResponse{
			Op: &pb.URNRegistryResponse_Register{
				Register: &pb.RegisterResponse{
					Ok:   false,
					Info: "unknown op",
				},
			},
		})
	}
}

func writeResp(stream network.Stream, resp *pb.URNRegistryResponse) {
	data, err := goproto.Marshal(resp)
	if err != nil {
		return
	}
	stream.Write(data)
}
