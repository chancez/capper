// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v4.25.2
// source: proto/capper/capper.proto

package capper

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CaptureRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filter            string               `protobuf:"bytes,1,opt,name=filter,proto3" json:"filter,omitempty"`
	NumPackets        uint64               `protobuf:"varint,2,opt,name=num_packets,json=numPackets,proto3" json:"num_packets,omitempty"`
	Duration          *durationpb.Duration `protobuf:"bytes,3,opt,name=duration,proto3" json:"duration,omitempty"`
	Interface         []string             `protobuf:"bytes,4,rep,name=interface,proto3" json:"interface,omitempty"`
	Snaplen           int64                `protobuf:"varint,5,opt,name=snaplen,proto3" json:"snaplen,omitempty"`
	Netns             string               `protobuf:"bytes,6,opt,name=netns,proto3" json:"netns,omitempty"`
	K8SPodFilter      *K8SPodFilter        `protobuf:"bytes,7,opt,name=k8s_pod_filter,json=k8sPodFilter,proto3" json:"k8s_pod_filter,omitempty"`
	NoPromiscuousMode bool                 `protobuf:"varint,8,opt,name=no_promiscuous_mode,json=noPromiscuousMode,proto3" json:"no_promiscuous_mode,omitempty"`
	BufferSize        int64                `protobuf:"varint,9,opt,name=buffer_size,json=bufferSize,proto3" json:"buffer_size,omitempty"`
}

func (x *CaptureRequest) Reset() {
	*x = CaptureRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_capper_capper_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CaptureRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CaptureRequest) ProtoMessage() {}

func (x *CaptureRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_capper_capper_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CaptureRequest.ProtoReflect.Descriptor instead.
func (*CaptureRequest) Descriptor() ([]byte, []int) {
	return file_proto_capper_capper_proto_rawDescGZIP(), []int{0}
}

func (x *CaptureRequest) GetFilter() string {
	if x != nil {
		return x.Filter
	}
	return ""
}

func (x *CaptureRequest) GetNumPackets() uint64 {
	if x != nil {
		return x.NumPackets
	}
	return 0
}

func (x *CaptureRequest) GetDuration() *durationpb.Duration {
	if x != nil {
		return x.Duration
	}
	return nil
}

func (x *CaptureRequest) GetInterface() []string {
	if x != nil {
		return x.Interface
	}
	return nil
}

func (x *CaptureRequest) GetSnaplen() int64 {
	if x != nil {
		return x.Snaplen
	}
	return 0
}

func (x *CaptureRequest) GetNetns() string {
	if x != nil {
		return x.Netns
	}
	return ""
}

func (x *CaptureRequest) GetK8SPodFilter() *K8SPodFilter {
	if x != nil {
		return x.K8SPodFilter
	}
	return nil
}

func (x *CaptureRequest) GetNoPromiscuousMode() bool {
	if x != nil {
		return x.NoPromiscuousMode
	}
	return false
}

func (x *CaptureRequest) GetBufferSize() int64 {
	if x != nil {
		return x.BufferSize
	}
	return 0
}

type K8SPodFilter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Namespace string `protobuf:"bytes,1,opt,name=namespace,proto3" json:"namespace,omitempty"`
	Pod       string `protobuf:"bytes,2,opt,name=pod,proto3" json:"pod,omitempty"`
}

func (x *K8SPodFilter) Reset() {
	*x = K8SPodFilter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_capper_capper_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *K8SPodFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*K8SPodFilter) ProtoMessage() {}

func (x *K8SPodFilter) ProtoReflect() protoreflect.Message {
	mi := &file_proto_capper_capper_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use K8SPodFilter.ProtoReflect.Descriptor instead.
func (*K8SPodFilter) Descriptor() ([]byte, []int) {
	return file_proto_capper_capper_proto_rawDescGZIP(), []int{1}
}

func (x *K8SPodFilter) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

func (x *K8SPodFilter) GetPod() string {
	if x != nil {
		return x.Pod
	}
	return ""
}

type CaptureResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data []byte `protobuf:"bytes,1,opt,name=data,proto3" json:"data,omitempty"`
}

func (x *CaptureResponse) Reset() {
	*x = CaptureResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_capper_capper_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CaptureResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CaptureResponse) ProtoMessage() {}

func (x *CaptureResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_capper_capper_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CaptureResponse.ProtoReflect.Descriptor instead.
func (*CaptureResponse) Descriptor() ([]byte, []int) {
	return file_proto_capper_capper_proto_rawDescGZIP(), []int{2}
}

func (x *CaptureResponse) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

var File_proto_capper_capper_proto protoreflect.FileDescriptor

var file_proto_capper_capper_proto_rawDesc = []byte{
	0x0a, 0x19, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2f, 0x63,
	0x61, 0x70, 0x70, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x63, 0x61, 0x70,
	0x70, 0x65, 0x72, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0xdb, 0x02, 0x0a, 0x0e, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x1f,
	0x0a, 0x0b, 0x6e, 0x75, 0x6d, 0x5f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x0a, 0x6e, 0x75, 0x6d, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x12,
	0x35, 0x0a, 0x08, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08, 0x64, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x1c, 0x0a, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66,
	0x61, 0x63, 0x65, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09, 0x52, 0x09, 0x69, 0x6e, 0x74, 0x65, 0x72,
	0x66, 0x61, 0x63, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x6e, 0x61, 0x70, 0x6c, 0x65, 0x6e, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x07, 0x73, 0x6e, 0x61, 0x70, 0x6c, 0x65, 0x6e, 0x12, 0x14,
	0x0a, 0x05, 0x6e, 0x65, 0x74, 0x6e, 0x73, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6e,
	0x65, 0x74, 0x6e, 0x73, 0x12, 0x3a, 0x0a, 0x0e, 0x6b, 0x38, 0x73, 0x5f, 0x70, 0x6f, 0x64, 0x5f,
	0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x63,
	0x61, 0x70, 0x70, 0x65, 0x72, 0x2e, 0x4b, 0x38, 0x73, 0x50, 0x6f, 0x64, 0x46, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x52, 0x0c, 0x6b, 0x38, 0x73, 0x50, 0x6f, 0x64, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x12, 0x2e, 0x0a, 0x13, 0x6e, 0x6f, 0x5f, 0x70, 0x72, 0x6f, 0x6d, 0x69, 0x73, 0x63, 0x75, 0x6f,
	0x75, 0x73, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x08, 0x20, 0x01, 0x28, 0x08, 0x52, 0x11, 0x6e,
	0x6f, 0x50, 0x72, 0x6f, 0x6d, 0x69, 0x73, 0x63, 0x75, 0x6f, 0x75, 0x73, 0x4d, 0x6f, 0x64, 0x65,
	0x12, 0x1f, 0x0a, 0x0b, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18,
	0x09, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0a, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x53, 0x69, 0x7a,
	0x65, 0x22, 0x3e, 0x0a, 0x0c, 0x4b, 0x38, 0x73, 0x50, 0x6f, 0x64, 0x46, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x12,
	0x10, 0x0a, 0x03, 0x70, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x70, 0x6f,
	0x64, 0x22, 0x25, 0x0a, 0x0f, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x04, 0x64, 0x61, 0x74, 0x61, 0x32, 0x48, 0x0a, 0x06, 0x43, 0x61, 0x70, 0x70,
	0x65, 0x72, 0x12, 0x3e, 0x0a, 0x07, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x12, 0x16, 0x2e,
	0x63, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2e, 0x43, 0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x63, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2e, 0x43,
	0x61, 0x70, 0x74, 0x75, 0x72, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00,
	0x30, 0x01, 0x42, 0x28, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x63, 0x68, 0x61, 0x6e, 0x63, 0x65, 0x7a, 0x2f, 0x63, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x63, 0x61, 0x70, 0x70, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_capper_capper_proto_rawDescOnce sync.Once
	file_proto_capper_capper_proto_rawDescData = file_proto_capper_capper_proto_rawDesc
)

func file_proto_capper_capper_proto_rawDescGZIP() []byte {
	file_proto_capper_capper_proto_rawDescOnce.Do(func() {
		file_proto_capper_capper_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_capper_capper_proto_rawDescData)
	})
	return file_proto_capper_capper_proto_rawDescData
}

var file_proto_capper_capper_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_proto_capper_capper_proto_goTypes = []interface{}{
	(*CaptureRequest)(nil),      // 0: capper.CaptureRequest
	(*K8SPodFilter)(nil),        // 1: capper.K8sPodFilter
	(*CaptureResponse)(nil),     // 2: capper.CaptureResponse
	(*durationpb.Duration)(nil), // 3: google.protobuf.Duration
}
var file_proto_capper_capper_proto_depIdxs = []int32{
	3, // 0: capper.CaptureRequest.duration:type_name -> google.protobuf.Duration
	1, // 1: capper.CaptureRequest.k8s_pod_filter:type_name -> capper.K8sPodFilter
	0, // 2: capper.Capper.Capture:input_type -> capper.CaptureRequest
	2, // 3: capper.Capper.Capture:output_type -> capper.CaptureResponse
	3, // [3:4] is the sub-list for method output_type
	2, // [2:3] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_proto_capper_capper_proto_init() }
func file_proto_capper_capper_proto_init() {
	if File_proto_capper_capper_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_capper_capper_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CaptureRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_capper_capper_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*K8SPodFilter); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_capper_capper_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CaptureResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_capper_capper_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_capper_capper_proto_goTypes,
		DependencyIndexes: file_proto_capper_capper_proto_depIdxs,
		MessageInfos:      file_proto_capper_capper_proto_msgTypes,
	}.Build()
	File_proto_capper_capper_proto = out.File
	file_proto_capper_capper_proto_rawDesc = nil
	file_proto_capper_capper_proto_goTypes = nil
	file_proto_capper_capper_proto_depIdxs = nil
}
