// Code generated by protoc-gen-go. DO NOT EDIT.
// source: workloadattestor.proto

/*
Package workloadattestor is a generated protocol buffer package.

It is generated from these files:
	workloadattestor.proto

It has these top-level messages:
	AttestRequest
	AttestResponse
*/
package workloadattestor

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

// * Represents the workload PID.
type AttestRequest struct {
	// * Workload PID
	Pid int32 `protobuf:"varint,1,opt,name=pid" json:"pid,omitempty"`
}

func (m *AttestRequest) Reset()                    { *m = AttestRequest{} }
func (m *AttestRequest) String() string            { return proto.CompactTextString(m) }
func (*AttestRequest) ProtoMessage()               {}
func (*AttestRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *AttestRequest) GetPid() int32 {
	if m != nil {
		return m.Pid
	}
	return 0
}

// * Represents a list of selectors resolved for a given PID.
type AttestResponse struct {
	// * List of selectors
	Selectors []string `protobuf:"bytes,1,rep,name=selectors" json:"selectors,omitempty"`
}

func (m *AttestResponse) Reset()                    { *m = AttestResponse{} }
func (m *AttestResponse) String() string            { return proto.CompactTextString(m) }
func (*AttestResponse) ProtoMessage()               {}
func (*AttestResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *AttestResponse) GetSelectors() []string {
	if m != nil {
		return m.Selectors
	}
	return nil
}

func init() {
	proto.RegisterType((*AttestRequest)(nil), "spire.agent.workloadattestor.AttestRequest")
	proto.RegisterType((*AttestResponse)(nil), "spire.agent.workloadattestor.AttestResponse")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for WorkloadAttestor service

type WorkloadAttestorClient interface {
	// * Returns a list of selectors resolved for a given PID
	Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error)
	// * Applies the plugin configuration and returns configuration errors
	Configure(ctx context.Context, in *spire_common_plugin.ConfigureRequest, opts ...grpc.CallOption) (*spire_common_plugin.ConfigureResponse, error)
	// * Returns the version and related metadata of the plugin
	GetPluginInfo(ctx context.Context, in *spire_common_plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*spire_common_plugin.GetPluginInfoResponse, error)
}

type workloadAttestorClient struct {
	cc *grpc.ClientConn
}

func NewWorkloadAttestorClient(cc *grpc.ClientConn) WorkloadAttestorClient {
	return &workloadAttestorClient{cc}
}

func (c *workloadAttestorClient) Attest(ctx context.Context, in *AttestRequest, opts ...grpc.CallOption) (*AttestResponse, error) {
	out := new(AttestResponse)
	err := grpc.Invoke(ctx, "/spire.agent.workloadattestor.WorkloadAttestor/Attest", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *workloadAttestorClient) Configure(ctx context.Context, in *spire_common_plugin.ConfigureRequest, opts ...grpc.CallOption) (*spire_common_plugin.ConfigureResponse, error) {
	out := new(spire_common_plugin.ConfigureResponse)
	err := grpc.Invoke(ctx, "/spire.agent.workloadattestor.WorkloadAttestor/Configure", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *workloadAttestorClient) GetPluginInfo(ctx context.Context, in *spire_common_plugin.GetPluginInfoRequest, opts ...grpc.CallOption) (*spire_common_plugin.GetPluginInfoResponse, error) {
	out := new(spire_common_plugin.GetPluginInfoResponse)
	err := grpc.Invoke(ctx, "/spire.agent.workloadattestor.WorkloadAttestor/GetPluginInfo", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for WorkloadAttestor service

type WorkloadAttestorServer interface {
	// * Returns a list of selectors resolved for a given PID
	Attest(context.Context, *AttestRequest) (*AttestResponse, error)
	// * Applies the plugin configuration and returns configuration errors
	Configure(context.Context, *spire_common_plugin.ConfigureRequest) (*spire_common_plugin.ConfigureResponse, error)
	// * Returns the version and related metadata of the plugin
	GetPluginInfo(context.Context, *spire_common_plugin.GetPluginInfoRequest) (*spire_common_plugin.GetPluginInfoResponse, error)
}

func RegisterWorkloadAttestorServer(s *grpc.Server, srv WorkloadAttestorServer) {
	s.RegisterService(&_WorkloadAttestor_serviceDesc, srv)
}

func _WorkloadAttestor_Attest_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AttestRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WorkloadAttestorServer).Attest(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.workloadattestor.WorkloadAttestor/Attest",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WorkloadAttestorServer).Attest(ctx, req.(*AttestRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WorkloadAttestor_Configure_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(spire_common_plugin.ConfigureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WorkloadAttestorServer).Configure(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.workloadattestor.WorkloadAttestor/Configure",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WorkloadAttestorServer).Configure(ctx, req.(*spire_common_plugin.ConfigureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WorkloadAttestor_GetPluginInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(spire_common_plugin.GetPluginInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WorkloadAttestorServer).GetPluginInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/spire.agent.workloadattestor.WorkloadAttestor/GetPluginInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WorkloadAttestorServer).GetPluginInfo(ctx, req.(*spire_common_plugin.GetPluginInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _WorkloadAttestor_serviceDesc = grpc.ServiceDesc{
	ServiceName: "spire.agent.workloadattestor.WorkloadAttestor",
	HandlerType: (*WorkloadAttestorServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Attest",
			Handler:    _WorkloadAttestor_Attest_Handler,
		},
		{
			MethodName: "Configure",
			Handler:    _WorkloadAttestor_Configure_Handler,
		},
		{
			MethodName: "GetPluginInfo",
			Handler:    _WorkloadAttestor_GetPluginInfo_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "workloadattestor.proto",
}

func init() { proto.RegisterFile("workloadattestor.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 271 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x91, 0xcd, 0x4a, 0xc3, 0x40,
	0x10, 0xc7, 0x8d, 0xc5, 0x42, 0x16, 0x2a, 0x61, 0x0f, 0x52, 0x4a, 0x0f, 0xb5, 0xa0, 0xd4, 0x0f,
	0x36, 0xa0, 0xbe, 0x40, 0xf5, 0x20, 0xde, 0x4a, 0x2e, 0x42, 0x6f, 0x69, 0x3a, 0xbb, 0x2e, 0x4d,
	0x76, 0xd6, 0xdd, 0x09, 0x3e, 0x9c, 0x2f, 0x27, 0x26, 0x1b, 0xa5, 0x45, 0x6c, 0x4f, 0x19, 0x32,
	0xbf, 0xf9, 0x7f, 0xb0, 0xec, 0xec, 0x03, 0xdd, 0xa6, 0xc4, 0x7c, 0x9d, 0x13, 0x81, 0x27, 0x74,
	0xc2, 0x3a, 0x24, 0xe4, 0x63, 0x6f, 0xb5, 0x03, 0x91, 0x2b, 0x30, 0x24, 0x76, 0x99, 0xd1, 0x83,
	0xd2, 0xf4, 0x56, 0xaf, 0x44, 0x81, 0x55, 0xea, 0xad, 0x96, 0x12, 0x52, 0xef, 0x74, 0x6a, 0x37,
	0x2a, 0x2d, 0xb0, 0xaa, 0xd0, 0xa4, 0xb6, 0xac, 0x95, 0xee, 0x3e, 0xad, 0xe6, 0xf4, 0x9c, 0x0d,
	0xe6, 0x8d, 0x42, 0x06, 0xef, 0x35, 0x78, 0xe2, 0x09, 0xeb, 0x59, 0xbd, 0x1e, 0x46, 0x93, 0x68,
	0x76, 0x92, 0x7d, 0x8f, 0x53, 0xc1, 0x4e, 0x3b, 0xc4, 0x5b, 0x34, 0x1e, 0xf8, 0x98, 0xc5, 0x1e,
	0x4a, 0x28, 0x08, 0x9d, 0x1f, 0x46, 0x93, 0xde, 0x2c, 0xce, 0x7e, 0x7f, 0xdc, 0x7d, 0x1e, 0xb3,
	0xe4, 0x35, 0xa4, 0x9b, 0x87, 0x74, 0xbc, 0x60, 0xfd, 0x76, 0xe6, 0x37, 0xe2, 0xbf, 0x1a, 0x62,
	0x2b, 0xcd, 0xe8, 0xf6, 0x30, 0x38, 0xe4, 0x5a, 0xb2, 0xf8, 0x09, 0x8d, 0xd4, 0xaa, 0x76, 0xc0,
	0x2f, 0xc2, 0x69, 0x5b, 0x5e, 0x84, 0xd6, 0x3f, 0xfb, 0xce, 0xe1, 0x72, 0x1f, 0x16, 0xb4, 0x25,
	0x1b, 0x3c, 0x03, 0x2d, 0x9a, 0xf5, 0x8b, 0x91, 0xc8, 0xaf, 0xfe, 0x3c, 0xdc, 0x62, 0x3a, 0x8f,
	0xeb, 0x43, 0xd0, 0xd6, 0xe7, 0x91, 0x2f, 0x93, 0xdd, 0x9a, 0x8b, 0xa3, 0x55, 0xbf, 0x79, 0xad,
	0xfb, 0xaf, 0x00, 0x00, 0x00, 0xff, 0xff, 0xbc, 0xb8, 0xc2, 0x62, 0x1b, 0x02, 0x00, 0x00,
}
