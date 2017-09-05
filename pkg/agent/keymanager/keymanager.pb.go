// Code generated by protoc-gen-go. DO NOT EDIT.
// source: keymanager.proto

/*
Package keymanager is a generated protocol buffer package.

It is generated from these files:
	keymanager.proto

It has these top-level messages:
	GenerateKeyPairRequest
	GenerateKeyPairResponse
	FetchPrivateKeyRequest
	FetchPrivateKeyResponse
*/
package keymanager

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import spire_common_plugin "github.com/spiffe/sri/pkg/common/plugin"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// ConfigureRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type ConfigureRequest spire_common_plugin.ConfigureRequest

func (m *ConfigureRequest) Reset()         { (*spire_common_plugin.ConfigureRequest)(m).Reset() }
func (m *ConfigureRequest) String() string { return (*spire_common_plugin.ConfigureRequest)(m).String() }
func (*ConfigureRequest) ProtoMessage()    {}
func (m *ConfigureRequest) GetConfiguration() string {
	return (*spire_common_plugin.ConfigureRequest)(m).GetConfiguration()
}

// ConfigureResponse from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type ConfigureResponse spire_common_plugin.ConfigureResponse

func (m *ConfigureResponse) Reset() { (*spire_common_plugin.ConfigureResponse)(m).Reset() }
func (m *ConfigureResponse) String() string {
	return (*spire_common_plugin.ConfigureResponse)(m).String()
}
func (*ConfigureResponse) ProtoMessage() {}
func (m *ConfigureResponse) GetErrorList() []string {
	return (*spire_common_plugin.ConfigureResponse)(m).GetErrorList()
}

// GetPluginInfoRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type GetPluginInfoRequest spire_common_plugin.GetPluginInfoRequest

func (m *GetPluginInfoRequest) Reset() { (*spire_common_plugin.GetPluginInfoRequest)(m).Reset() }
func (m *GetPluginInfoRequest) String() string {
	return (*spire_common_plugin.GetPluginInfoRequest)(m).String()
}
func (*GetPluginInfoRequest) ProtoMessage() {}

// GetPluginInfoResponse from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type GetPluginInfoResponse spire_common_plugin.GetPluginInfoResponse

func (m *GetPluginInfoResponse) Reset() { (*spire_common_plugin.GetPluginInfoResponse)(m).Reset() }
func (m *GetPluginInfoResponse) String() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).String()
}
func (*GetPluginInfoResponse) ProtoMessage() {}
func (m *GetPluginInfoResponse) GetName() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetName()
}
func (m *GetPluginInfoResponse) GetCategory() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetCategory()
}
func (m *GetPluginInfoResponse) GetType() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetType()
}
func (m *GetPluginInfoResponse) GetDescription() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetDescription()
}
func (m *GetPluginInfoResponse) GetDateCreated() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetDateCreated()
}
func (m *GetPluginInfoResponse) GetLocation() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetLocation()
}
func (m *GetPluginInfoResponse) GetVersion() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetVersion()
}
func (m *GetPluginInfoResponse) GetAuthor() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetAuthor()
}
func (m *GetPluginInfoResponse) GetCompany() string {
	return (*spire_common_plugin.GetPluginInfoResponse)(m).GetCompany()
}

// PluginInfoRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type PluginInfoRequest spire_common_plugin.PluginInfoRequest

func (m *PluginInfoRequest) Reset() { (*spire_common_plugin.PluginInfoRequest)(m).Reset() }
func (m *PluginInfoRequest) String() string {
	return (*spire_common_plugin.PluginInfoRequest)(m).String()
}
func (*PluginInfoRequest) ProtoMessage() {}

// PluginInfoReply from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type PluginInfoReply spire_common_plugin.PluginInfoReply

func (m *PluginInfoReply) Reset()         { (*spire_common_plugin.PluginInfoReply)(m).Reset() }
func (m *PluginInfoReply) String() string { return (*spire_common_plugin.PluginInfoReply)(m).String() }
func (*PluginInfoReply) ProtoMessage()    {}
func (m *PluginInfoReply) GetPluginInfo() []*GetPluginInfoResponse {
	o := (*spire_common_plugin.PluginInfoReply)(m).GetPluginInfo()
	if o == nil {
		return nil
	}
	s := make([]*GetPluginInfoResponse, len(o))
	for i, x := range o {
		s[i] = (*GetPluginInfoResponse)(x)
	}
	return s
}

// StopRequest from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type StopRequest spire_common_plugin.StopRequest

func (m *StopRequest) Reset()         { (*spire_common_plugin.StopRequest)(m).Reset() }
func (m *StopRequest) String() string { return (*spire_common_plugin.StopRequest)(m).String() }
func (*StopRequest) ProtoMessage()    {}

// StopReply from public import github.com/spiffe/sri/pkg/common/plugin/plugin.proto
type StopReply spire_common_plugin.StopReply

func (m *StopReply) Reset()         { (*spire_common_plugin.StopReply)(m).Reset() }
func (m *StopReply) String() string { return (*spire_common_plugin.StopReply)(m).String() }
func (*StopReply) ProtoMessage()    {}

// * Represents an empty request
type GenerateKeyPairRequest struct {
}

func (m *GenerateKeyPairRequest) Reset()                    { *m = GenerateKeyPairRequest{} }
func (m *GenerateKeyPairRequest) String() string            { return proto.CompactTextString(m) }
func (*GenerateKeyPairRequest) ProtoMessage()               {}
func (*GenerateKeyPairRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

// * Represents a public and private key pair
type GenerateKeyPairResponse struct {
	// * Public key
	PublicKey []byte `protobuf:"bytes,1,opt,name=publicKey,proto3" json:"publicKey,omitempty"`
	// * Private key
	PrivateKey []byte `protobuf:"bytes,2,opt,name=privateKey,proto3" json:"privateKey,omitempty"`
}

func (m *GenerateKeyPairResponse) Reset()                    { *m = GenerateKeyPairResponse{} }
func (m *GenerateKeyPairResponse) String() string            { return proto.CompactTextString(m) }
func (*GenerateKeyPairResponse) ProtoMessage()               {}
func (*GenerateKeyPairResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *GenerateKeyPairResponse) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *GenerateKeyPairResponse) GetPrivateKey() []byte {
	if m != nil {
		return m.PrivateKey
	}
	return nil
}

// * Represents an empty request
type FetchPrivateKeyRequest struct {
}

func (m *FetchPrivateKeyRequest) Reset()                    { *m = FetchPrivateKeyRequest{} }
func (m *FetchPrivateKeyRequest) String() string            { return proto.CompactTextString(m) }
func (*FetchPrivateKeyRequest) ProtoMessage()               {}
func (*FetchPrivateKeyRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

// * Represents a private key
type FetchPrivateKeyResponse struct {
	// * Priavte key
	PrivateKey []byte `protobuf:"bytes,1,opt,name=privateKey,proto3" json:"privateKey,omitempty"`
}

func (m *FetchPrivateKeyResponse) Reset()                    { *m = FetchPrivateKeyResponse{} }
func (m *FetchPrivateKeyResponse) String() string            { return proto.CompactTextString(m) }
func (*FetchPrivateKeyResponse) ProtoMessage()               {}
func (*FetchPrivateKeyResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *FetchPrivateKeyResponse) GetPrivateKey() []byte {
	if m != nil {
		return m.PrivateKey
	}
	return nil
}

func init() {
	proto.RegisterType((*GenerateKeyPairRequest)(nil), "spire.agent.keymanager.GenerateKeyPairRequest")
	proto.RegisterType((*GenerateKeyPairResponse)(nil), "spire.agent.keymanager.GenerateKeyPairResponse")
	proto.RegisterType((*FetchPrivateKeyRequest)(nil), "spire.agent.keymanager.FetchPrivateKeyRequest")
	proto.RegisterType((*FetchPrivateKeyResponse)(nil), "spire.agent.keymanager.FetchPrivateKeyResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for KeyManager service

type KeyManagerClient interface {
	// * Creates a key pair that is bound to hardware.
	GenerateKeyPair(ctx context.Context, in *GenerateKeyPairRequest, opts ...grpc.CallOption) (*GenerateKeyPairResponse, error)
	// * Returns previously generated private key. For use after node restarts.
	FetchPrivateKey(ctx context.Context, in *FetchPrivateKeyRequest, opts ...grpc.CallOption) (*FetchPrivateKeyResponse, error)
	// * Applies the plugin configuration and returns configuration errors.
	Configure(ctx context.Context, in *spire_common_plugin.ConfigureRequest, opts ...grpc.CallOption) (*spire_common_plugin.ConfigureResponse, error)
	// * Returns the version and related metadata of the plugin.
	GetPluginInfo(ctx context.Context, in *spire_common_plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*spire_common_plugin.GetPluginInfoResponse, error)
}

type keyManagerClient struct {
	cc *grpc.ClientConn
}

func NewKeyManagerClient(cc *grpc.ClientConn) KeyManagerClient {
	return &keyManagerClient{cc}
}

func (c *keyManagerClient) GenerateKeyPair(ctx context.Context, in *GenerateKeyPairRequest, opts ...grpc.CallOption) (*GenerateKeyPairResponse, error) {
	out := new(GenerateKeyPairResponse)
	err := grpc.Invoke(ctx, "/spire.agent.keymanager.KeyManager/GenerateKeyPair", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) FetchPrivateKey(ctx context.Context, in *FetchPrivateKeyRequest, opts ...grpc.CallOption) (*FetchPrivateKeyResponse, error) {
	out := new(FetchPrivateKeyResponse)
	err := grpc.Invoke(ctx, "/spire.agent.keymanager.KeyManager/FetchPrivateKey", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) Configure(ctx context.Context, in *spire_common_plugin.ConfigureRequest, opts ...grpc.CallOption) (*spire_common_plugin.ConfigureResponse, error) {
	out := new(spire_common_plugin.ConfigureResponse)
	err := grpc.Invoke(ctx, "/spire.agent.keymanager.KeyManager/Configure", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *keyManagerClient) GetPluginInfo(ctx context.Context, in *spire_common_plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*spire_common_plugin.GetPluginInfoResponse, error) {
	out := new(spire_common_plugin.GetPluginInfoResponse)
	err := grpc.Invoke(ctx, "/spire.agent.keymanager.KeyManager/GetPluginInfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for KeyManager service

type KeyManagerServer interface {
	// * Creates a key pair that is bound to hardware.
	GenerateKeyPair(context.Context, *GenerateKeyPairRequest) (*GenerateKeyPairResponse, error)
	// * Returns previously generated private key. For use after node restarts.
	FetchPrivateKey(context.Context, *FetchPrivateKeyRequest) (*FetchPrivateKeyResponse, error)
	// * Applies the plugin configuration and returns configuration errors.
	Configure(context.Context, *spire_common_plugin.ConfigureRequest) (*spire_common_plugin.ConfigureResponse, error)
	// * Returns the version and related metadata of the plugin.
	GetPluginInfo(context.Context, *spire_common_plugin.GetPluginInfoRequest) (*spire_common_plugin.GetPluginInfoResponse, error)
}

func RegisterKeyManagerServer(s *grpc.Server, srv KeyManagerServer) {
	s.RegisterService(&_KeyManager_serviceDesc, srv)
}

func _KeyManager_GenerateKeyPair_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GenerateKeyPairRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).GenerateKeyPair(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.keymanager.KeyManager/GenerateKeyPair",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).GenerateKeyPair(ctx, req.(*GenerateKeyPairRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_FetchPrivateKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(FetchPrivateKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).FetchPrivateKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.keymanager.KeyManager/FetchPrivateKey",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).FetchPrivateKey(ctx, req.(*FetchPrivateKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(spire_common_plugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.keymanager.KeyManager/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).Configure(ctx, req.(*spire_common_plugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _KeyManager_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(spire_common_plugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(KeyManagerServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.keymanager.KeyManager/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(KeyManagerServer).GetPluginInfo(ctx, req.(*spire_common_plugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _KeyManager_serviceDesc = grpc.ServiceDesc{
	ServiceName: "spire.agent.keymanager.KeyManager",
	HandlerType: (*KeyManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GenerateKeyPair",
			Handler:    _KeyManager_GenerateKeyPair_Handler,
		},
		{
			MethodName: "FetchPrivateKey",
			Handler:    _KeyManager_FetchPrivateKey_Handler,
		},
		{
			MethodName: "Configure",
			Handler:    _KeyManager_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _KeyManager_GetPluginInfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "keymanager.proto",
}

func init() { proto.RegisterFile("keymanager.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 314 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x4f, 0x4b, 0xf3, 0x40,
	0x10, 0xc6, 0xdf, 0xbe, 0x82, 0xd0, 0xa1, 0x52, 0xd9, 0x43, 0x5b, 0x8a, 0x88, 0x14, 0x14, 0xf5,
	0xb0, 0x0b, 0xea, 0xc5, 0xab, 0x82, 0x45, 0x82, 0x10, 0x7a, 0x11, 0x7a, 0x4b, 0xc2, 0x64, 0xbb,
	0xb4, 0xd9, 0x5d, 0x77, 0x37, 0x42, 0xbe, 0x99, 0x1f, 0x4f, 0xcc, 0x9f, 0xc6, 0xa6, 0x09, 0xf6,
	0x14, 0x98, 0x67, 0xe6, 0xf9, 0xcd, 0x3e, 0x13, 0x38, 0x5d, 0x63, 0x96, 0x04, 0x32, 0xe0, 0x68,
	0xa8, 0x36, 0xca, 0x29, 0x32, 0xb2, 0x5a, 0x18, 0xa4, 0x01, 0x47, 0xe9, 0x68, 0xad, 0x4e, 0x1f,
	0xb8, 0x70, 0xab, 0x34, 0xa4, 0x91, 0x4a, 0x98, 0xd5, 0x22, 0x8e, 0x91, 0x59, 0x23, 0x98, 0x5e,
	0x73, 0x16, 0xa9, 0x24, 0x51, 0x92, 0xe9, 0x4d, 0xca, 0x45, 0xf5, 0x29, 0xdc, 0x66, 0x13, 0x18,
	0xcd, 0x51, 0xa2, 0x09, 0x1c, 0x7a, 0x98, 0xf9, 0x81, 0x30, 0x0b, 0xfc, 0x48, 0xd1, 0xba, 0xd9,
	0x3b, 0x8c, 0xf7, 0x14, 0xab, 0x95, 0xb4, 0x48, 0xce, 0xa0, 0xaf, 0xd3, 0x70, 0x23, 0x22, 0x0f,
	0xb3, 0x49, 0xef, 0xa2, 0x77, 0x3d, 0x58, 0xd4, 0x05, 0x72, 0x0e, 0xa0, 0x8d, 0xf8, 0x2c, 0xe6,
	0x26, 0xff, 0x73, 0xf9, 0x57, 0xe5, 0x07, 0xf9, 0x82, 0x2e, 0x5a, 0xf9, 0xdb, 0x52, 0x85, 0x7c,
	0x84, 0xf1, 0x9e, 0x52, 0x22, 0x77, 0x4d, 0x7b, 0x4d, 0xd3, 0xbb, 0xaf, 0x23, 0x00, 0x0f, 0xb3,
	0xb7, 0x22, 0x0c, 0x62, 0x60, 0xd8, 0x58, 0x9e, 0x50, 0xda, 0x1e, 0x1c, 0x6d, 0x7f, 0xff, 0x94,
	0x1d, 0xdc, 0x5f, 0xae, 0x68, 0x60, 0xd8, 0xd8, 0xbe, 0x9b, 0xd9, 0x1e, 0x40, 0x37, 0xb3, 0x2b,
	0x96, 0x25, 0xf4, 0x9f, 0x95, 0x8c, 0x05, 0x4f, 0x0d, 0x92, 0xcb, 0x72, 0xba, 0x38, 0x37, 0x2d,
	0xef, 0xbc, 0xd5, 0x2b, 0xc8, 0xd5, 0x5f, 0x6d, 0xa5, 0x77, 0x0c, 0x27, 0x73, 0x74, 0x7e, 0x2e,
	0xbf, 0xca, 0x58, 0x91, 0x9b, 0xd6, 0xc1, 0x9d, 0x9e, 0x8a, 0x71, 0x7b, 0x48, 0x6b, 0xc1, 0x79,
	0x1a, 0x2c, 0xa1, 0x7e, 0xa9, 0xff, 0x2f, 0x3c, 0xce, 0xff, 0xcc, 0xfb, 0xef, 0x00, 0x00, 0x00,
	0xff, 0xff, 0x1a, 0xf9, 0xb2, 0x97, 0xfb, 0x02, 0x00, 0x00,
}
