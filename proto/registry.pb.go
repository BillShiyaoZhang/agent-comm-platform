package proto

type URNRegistryRequest struct {
	Op isURNRegistryRequest_Op
}
type isURNRegistryRequest_Op interface{ isURNRegistryRequest_Op() }
type URNRegistryRequest_Register struct{ Register *RegisterRequest }
type URNRegistryRequest_Resolve struct{ Resolve *ResolveRequest }
func (*URNRegistryRequest_Register) isURNRegistryRequest_Op() {}
func (*URNRegistryRequest_Resolve) isURNRegistryRequest_Op()  {}
func (x *URNRegistryRequest) GetOp() isURNRegistryRequest_Op { return x.Op }
func (x *URNRegistryRequest) GetRegister() *RegisterRequest {
	if v, ok := x.Op.(*URNRegistryRequest_Register); ok { return v.Register }; return nil
}
func (x *URNRegistryRequest) GetResolve() *ResolveRequest {
	if v, ok := x.Op.(*URNRegistryRequest_Resolve); ok { return v.Resolve }; return nil
}

type RegisterRequest struct {
	Urn          string   `protobuf:"bytes,1,opt,name=urn,proto3"`
	PeerId       string   `protobuf:"bytes,2,opt,name=peer_id,json=peerId,proto3"`
	Addrs        []string `protobuf:"bytes,3,rep,name=addrs,proto3"`
	X25519Pubkey []byte   `protobuf:"bytes,4,opt,name=x25519_pubkey,json=x25519Pubkey,proto3"`
}
func (x *RegisterRequest) GetUrn() string          { if x != nil { return x.Urn }; return "" }
func (x *RegisterRequest) GetPeerId() string       { if x != nil { return x.PeerId }; return "" }
func (x *RegisterRequest) GetAddrs() []string      { if x != nil { return x.Addrs }; return nil }
func (x *RegisterRequest) GetX25519Pubkey() []byte { if x != nil { return x.X25519Pubkey }; return nil }

type ResolveRequest struct {
	Urn string `protobuf:"bytes,1,opt,name=urn,proto3"`
}
func (x *ResolveRequest) GetUrn() string { if x != nil { return x.Urn }; return "" }

type URNRegistryResponse struct {
	Op isURNRegistryResponse_Op
}
type isURNRegistryResponse_Op interface{ isURNRegistryResponse_Op() }
type URNRegistryResponse_Register struct{ Register *RegisterResponse }
type URNRegistryResponse_Resolve struct{ Resolve *ResolveResponse }
func (*URNRegistryResponse_Register) isURNRegistryResponse_Op() {}
func (*URNRegistryResponse_Resolve) isURNRegistryResponse_Op()  {}
func (x *URNRegistryResponse) GetOp() isURNRegistryResponse_Op { return x.Op }
func (x *URNRegistryResponse) GetRegister() *RegisterResponse {
	if v, ok := x.Op.(*URNRegistryResponse_Register); ok { return v.Register }; return nil
}
func (x *URNRegistryResponse) GetResolve() *ResolveResponse {
	if v, ok := x.Op.(*URNRegistryResponse_Resolve); ok { return v.Resolve }; return nil
}

type RegisterResponse struct {
	Ok   bool   `protobuf:"varint,1,opt,name=ok,proto3"`
	Info string `protobuf:"bytes,2,opt,name=info,proto3"`
}
func (x *RegisterResponse) GetOk() bool    { if x != nil { return x.Ok }; return false }
func (x *RegisterResponse) GetInfo() string { if x != nil { return x.Info }; return "" }

type ResolveResponse struct {
	Found        bool     `protobuf:"varint,1,opt,name=found,proto3"`
	PeerId       string   `protobuf:"bytes,2,opt,name=peer_id,json=peerId,proto3"`
	Addrs        []string `protobuf:"bytes,3,rep,name=addrs,proto3"`
	X25519Pubkey []byte   `protobuf:"bytes,4,opt,name=x25519_pubkey,json=x25519Pubkey,proto3"`
}
func (x *ResolveResponse) GetFound() bool          { if x != nil { return x.Found }; return false }
func (x *ResolveResponse) GetPeerId() string       { if x != nil { return x.PeerId }; return "" }
func (x *ResolveResponse) GetAddrs() []string      { if x != nil { return x.Addrs }; return nil }
func (x *ResolveResponse) GetX25519Pubkey() []byte { if x != nil { return x.X25519Pubkey }; return nil }
