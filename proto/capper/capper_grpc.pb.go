// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.25.2
// source: proto/capper/capper.proto

package capper

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// CapperClient is the client API for Capper service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type CapperClient interface {
	Capture(ctx context.Context, in *CaptureRequest, opts ...grpc.CallOption) (*CaptureResponse, error)
}

type capperClient struct {
	cc grpc.ClientConnInterface
}

func NewCapperClient(cc grpc.ClientConnInterface) CapperClient {
	return &capperClient{cc}
}

func (c *capperClient) Capture(ctx context.Context, in *CaptureRequest, opts ...grpc.CallOption) (*CaptureResponse, error) {
	out := new(CaptureResponse)
	err := c.cc.Invoke(ctx, "/capper.Capper/Capture", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CapperServer is the server API for Capper service.
// All implementations must embed UnimplementedCapperServer
// for forward compatibility
type CapperServer interface {
	Capture(context.Context, *CaptureRequest) (*CaptureResponse, error)
	mustEmbedUnimplementedCapperServer()
}

// UnimplementedCapperServer must be embedded to have forward compatible implementations.
type UnimplementedCapperServer struct {
}

func (UnimplementedCapperServer) Capture(context.Context, *CaptureRequest) (*CaptureResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Capture not implemented")
}
func (UnimplementedCapperServer) mustEmbedUnimplementedCapperServer() {}

// UnsafeCapperServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to CapperServer will
// result in compilation errors.
type UnsafeCapperServer interface {
	mustEmbedUnimplementedCapperServer()
}

func RegisterCapperServer(s grpc.ServiceRegistrar, srv CapperServer) {
	s.RegisterService(&Capper_ServiceDesc, srv)
}

func _Capper_Capture_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CaptureRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(CapperServer).Capture(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/capper.Capper/Capture",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(CapperServer).Capture(ctx, req.(*CaptureRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// Capper_ServiceDesc is the grpc.ServiceDesc for Capper service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Capper_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "capper.Capper",
	HandlerType: (*CapperServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Capture",
			Handler:    _Capper_Capture_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/capper/capper.proto",
}
