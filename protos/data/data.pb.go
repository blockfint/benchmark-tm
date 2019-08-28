// Code generated by protoc-gen-go. DO NOT EDIT.
// source: protos/data/data.proto

package data

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
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

type NodeDetail struct {
	PublicKey            string   `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	MasterPublicKey      string   `protobuf:"bytes,2,opt,name=master_public_key,json=masterPublicKey,proto3" json:"master_public_key,omitempty"`
	NodeName             string   `protobuf:"bytes,3,opt,name=node_name,json=nodeName,proto3" json:"node_name,omitempty"`
	Active               bool     `protobuf:"varint,4,opt,name=active,proto3" json:"active,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *NodeDetail) Reset()         { *m = NodeDetail{} }
func (m *NodeDetail) String() string { return proto.CompactTextString(m) }
func (*NodeDetail) ProtoMessage()    {}
func (*NodeDetail) Descriptor() ([]byte, []int) {
	return fileDescriptor_492be2f0ffbab25c, []int{0}
}

func (m *NodeDetail) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_NodeDetail.Unmarshal(m, b)
}
func (m *NodeDetail) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_NodeDetail.Marshal(b, m, deterministic)
}
func (m *NodeDetail) XXX_Merge(src proto.Message) {
	xxx_messageInfo_NodeDetail.Merge(m, src)
}
func (m *NodeDetail) XXX_Size() int {
	return xxx_messageInfo_NodeDetail.Size(m)
}
func (m *NodeDetail) XXX_DiscardUnknown() {
	xxx_messageInfo_NodeDetail.DiscardUnknown(m)
}

var xxx_messageInfo_NodeDetail proto.InternalMessageInfo

func (m *NodeDetail) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func (m *NodeDetail) GetMasterPublicKey() string {
	if m != nil {
		return m.MasterPublicKey
	}
	return ""
}

func (m *NodeDetail) GetNodeName() string {
	if m != nil {
		return m.NodeName
	}
	return ""
}

func (m *NodeDetail) GetActive() bool {
	if m != nil {
		return m.Active
	}
	return false
}

func init() {
	proto.RegisterType((*NodeDetail)(nil), "NodeDetail")
}

func init() { proto.RegisterFile("protos/data/data.proto", fileDescriptor_492be2f0ffbab25c) }

var fileDescriptor_492be2f0ffbab25c = []byte{
	// 152 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x12, 0x2b, 0x28, 0xca, 0x2f,
	0xc9, 0x2f, 0xd6, 0x4f, 0x49, 0x2c, 0x49, 0x04, 0x13, 0x7a, 0x60, 0x01, 0xa5, 0x1e, 0x46, 0x2e,
	0x2e, 0xbf, 0xfc, 0x94, 0x54, 0x97, 0xd4, 0x92, 0xc4, 0xcc, 0x1c, 0x21, 0x59, 0x2e, 0xae, 0x82,
	0xd2, 0xa4, 0x9c, 0xcc, 0xe4, 0xf8, 0xec, 0xd4, 0x4a, 0x09, 0x46, 0x05, 0x46, 0x0d, 0xce, 0x20,
	0x4e, 0x88, 0x88, 0x77, 0x6a, 0xa5, 0x90, 0x16, 0x97, 0x60, 0x6e, 0x62, 0x71, 0x49, 0x6a, 0x51,
	0x3c, 0x92, 0x2a, 0x26, 0xb0, 0x2a, 0x7e, 0x88, 0x44, 0x00, 0x5c, 0xad, 0x34, 0x17, 0x67, 0x5e,
	0x7e, 0x4a, 0x6a, 0x7c, 0x5e, 0x62, 0x6e, 0xaa, 0x04, 0x33, 0x58, 0x0d, 0x07, 0x48, 0xc0, 0x2f,
	0x31, 0x37, 0x55, 0x48, 0x8c, 0x8b, 0x2d, 0x31, 0xb9, 0x24, 0xb3, 0x2c, 0x55, 0x82, 0x45, 0x81,
	0x51, 0x83, 0x23, 0x08, 0xca, 0x4b, 0x62, 0x03, 0xbb, 0xca, 0x18, 0x10, 0x00, 0x00, 0xff, 0xff,
	0x4b, 0x5f, 0x46, 0x48, 0xaf, 0x00, 0x00, 0x00,
}
