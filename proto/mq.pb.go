package proto

// MQ protocol types — same protobuf field tags as agent-comm wire format.

type MQRequest struct {
	Op isMQRequest_Op
}
type isMQRequest_Op interface{ isMQRequest_Op() }
type MQRequest_Store struct{ Store *StoreRequest }
type MQRequest_Retrieve struct{ Retrieve *RetrieveRequest }
type MQRequest_Ack struct{ Ack *AckRequest }
func (*MQRequest_Store) isMQRequest_Op()    {}
func (*MQRequest_Retrieve) isMQRequest_Op() {}
func (*MQRequest_Ack) isMQRequest_Op()      {}
func (x *MQRequest) GetOp() isMQRequest_Op  { return x.Op }
func (x *MQRequest) GetStore() *StoreRequest {
	if v, ok := x.Op.(*MQRequest_Store); ok { return v.Store }; return nil
}
func (x *MQRequest) GetRetrieve() *RetrieveRequest {
	if v, ok := x.Op.(*MQRequest_Retrieve); ok { return v.Retrieve }; return nil
}
func (x *MQRequest) GetAck() *AckRequest {
	if v, ok := x.Op.(*MQRequest_Ack); ok { return v.Ack }; return nil
}

type StoreRequest struct {
	RecipientUrn string             `protobuf:"bytes,1,opt,name=recipient_urn,json=recipientUrn,proto3"`
	Payload      *EncryptedEnvelope `protobuf:"bytes,2,opt,name=payload,proto3"`
	ExpiryUnix   int64              `protobuf:"varint,3,opt,name=expiry_unix,json=expiryUnix,proto3"`
}
func (x *StoreRequest) GetRecipientUrn() string {
	if x != nil { return x.RecipientUrn }; return ""
}
func (x *StoreRequest) GetPayload() *EncryptedEnvelope {
	if x != nil { return x.Payload }; return nil
}
func (x *StoreRequest) GetExpiryUnix() int64 {
	if x != nil { return x.ExpiryUnix }; return 0
}

type RetrieveRequest struct {
	RecipientUrn string `protobuf:"bytes,1,opt,name=recipient_urn,json=recipientUrn,proto3"`
}
func (x *RetrieveRequest) GetRecipientUrn() string {
	if x != nil { return x.RecipientUrn }; return ""
}

type AckRequest struct {
	MessageIds []string `protobuf:"bytes,1,rep,name=message_ids,json=messageIds,proto3"`
}
func (x *AckRequest) GetMessageIds() []string {
	if x != nil { return x.MessageIds }; return nil
}

type MQResponse struct {
	Op isMQResponse_Op
}
type isMQResponse_Op interface{ isMQResponse_Op() }
type MQResponse_Store struct{ Store *StoreResponse }
type MQResponse_Retrieve struct{ Retrieve *RetrieveResponse }
type MQResponse_Ack struct{ Ack *AckResponse }
type MQResponse_Error struct{ Error *ErrorResponse }
func (*MQResponse_Store) isMQResponse_Op()    {}
func (*MQResponse_Retrieve) isMQResponse_Op() {}
func (*MQResponse_Ack) isMQResponse_Op()      {}
func (*MQResponse_Error) isMQResponse_Op()    {}
func (x *MQResponse) GetOp() isMQResponse_Op  { return x.Op }
func (x *MQResponse) GetStore() *StoreResponse {
	if v, ok := x.Op.(*MQResponse_Store); ok { return v.Store }; return nil
}
func (x *MQResponse) GetRetrieve() *RetrieveResponse {
	if v, ok := x.Op.(*MQResponse_Retrieve); ok { return v.Retrieve }; return nil
}
func (x *MQResponse) GetAck() *AckResponse {
	if v, ok := x.Op.(*MQResponse_Ack); ok { return v.Ack }; return nil
}
func (x *MQResponse) GetError() *ErrorResponse {
	if v, ok := x.Op.(*MQResponse_Error); ok { return v.Error }; return nil
}

type StoreResponse struct {
	Ok        bool   `protobuf:"varint,1,opt,name=ok,proto3"`
	MessageId string `protobuf:"bytes,2,opt,name=message_id,json=messageId,proto3"`
}
func (x *StoreResponse) GetOk() bool        { if x != nil { return x.Ok }; return false }
func (x *StoreResponse) GetMessageId() string { if x != nil { return x.MessageId }; return "" }

type RetrieveResponse struct {
	Payloads []*EncryptedEnvelope `protobuf:"bytes,1,rep,name=payloads,proto3"`
}
func (x *RetrieveResponse) GetPayloads() []*EncryptedEnvelope {
	if x != nil { return x.Payloads }; return nil
}

type AckResponse struct {
	Ok           bool  `protobuf:"varint,1,opt,name=ok,proto3"`
	DeletedCount int32 `protobuf:"varint,2,opt,name=deleted_count,json=deletedCount,proto3"`
}
func (x *AckResponse) GetOk() bool            { if x != nil { return x.Ok }; return false }
func (x *AckResponse) GetDeletedCount() int32  { if x != nil { return x.DeletedCount }; return 0 }

type ErrorResponse struct {
	Message string `protobuf:"bytes,1,opt,name=message,proto3"`
}
func (x *ErrorResponse) GetMessage() string { if x != nil { return x.Message }; return "" }
