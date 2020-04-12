// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.20.1
// 	protoc        v3.11.4
// source: gateway/proto/analytics.proto

package pb

import (
	reflect "reflect"
	sync "sync"

	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamp "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
//const _ = proto.ProtoPackageIsVersion4

type AnalyticsRecord_Latency struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Total    int64 `protobuf:"varint,1,opt,name=Total,proto3" json:"Total,omitempty"`
	Upstream int64 `protobuf:"varint,2,opt,name=Upstream,proto3" json:"Upstream,omitempty"`
}

func (x *AnalyticsRecord_Latency) Reset() {
	*x = AnalyticsRecord_Latency{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyticsRecord_Latency) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyticsRecord_Latency) ProtoMessage() {}

func (x *AnalyticsRecord_Latency) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyticsRecord_Latency.ProtoReflect.Descriptor instead.
func (*AnalyticsRecord_Latency) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{0}
}

func (x *AnalyticsRecord_Latency) GetTotal() int64 {
	if x != nil {
		return x.Total
	}
	return 0
}

func (x *AnalyticsRecord_Latency) GetUpstream() int64 {
	if x != nil {
		return x.Upstream
	}
	return 0
}

type GeoData_Country struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ISOCode string `protobuf:"bytes,1,opt,name=ISOCode,proto3" json:"ISOCode,omitempty"`
}

func (x *GeoData_Country) Reset() {
	*x = GeoData_Country{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoData_Country) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoData_Country) ProtoMessage() {}

func (x *GeoData_Country) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoData_Country.ProtoReflect.Descriptor instead.
func (*GeoData_Country) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{1}
}

func (x *GeoData_Country) GetISOCode() string {
	if x != nil {
		return x.ISOCode
	}
	return ""
}

type GeoData_City struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Names map[string]string `protobuf:"bytes,1,rep,name=Names,proto3" json:"Names,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *GeoData_City) Reset() {
	*x = GeoData_City{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoData_City) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoData_City) ProtoMessage() {}

func (x *GeoData_City) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoData_City.ProtoReflect.Descriptor instead.
func (*GeoData_City) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{2}
}

func (x *GeoData_City) GetNames() map[string]string {
	if x != nil {
		return x.Names
	}
	return nil
}

type GeoData_Location struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Latitude  float64 `protobuf:"fixed64,1,opt,name=Latitude,proto3" json:"Latitude,omitempty"`
	Longitude float64 `protobuf:"fixed64,2,opt,name=Longitude,proto3" json:"Longitude,omitempty"`
	TimeZone  string  `protobuf:"bytes,3,opt,name=TimeZone,proto3" json:"TimeZone,omitempty"`
}

func (x *GeoData_Location) Reset() {
	*x = GeoData_Location{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeoData_Location) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeoData_Location) ProtoMessage() {}

func (x *GeoData_Location) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeoData_Location.ProtoReflect.Descriptor instead.
func (*GeoData_Location) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{3}
}

func (x *GeoData_Location) GetLatitude() float64 {
	if x != nil {
		return x.Latitude
	}
	return 0
}

func (x *GeoData_Location) GetLongitude() float64 {
	if x != nil {
		return x.Longitude
	}
	return 0
}

func (x *GeoData_Location) GetTimeZone() string {
	if x != nil {
		return x.TimeZone
	}
	return ""
}

type AnalyticsRecord_GeoData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Country  *GeoData_Country  `protobuf:"bytes,1,opt,name=Country,proto3" json:"Country,omitempty"`
	City     *GeoData_City     `protobuf:"bytes,2,opt,name=City,proto3" json:"City,omitempty"`
	Location *GeoData_Location `protobuf:"bytes,3,opt,name=Location,proto3" json:"Location,omitempty"`
}

func (x *AnalyticsRecord_GeoData) Reset() {
	*x = AnalyticsRecord_GeoData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyticsRecord_GeoData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyticsRecord_GeoData) ProtoMessage() {}

func (x *AnalyticsRecord_GeoData) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyticsRecord_GeoData.ProtoReflect.Descriptor instead.
func (*AnalyticsRecord_GeoData) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{4}
}

func (x *AnalyticsRecord_GeoData) GetCountry() *GeoData_Country {
	if x != nil {
		return x.Country
	}
	return nil
}

func (x *AnalyticsRecord_GeoData) GetCity() *GeoData_City {
	if x != nil {
		return x.City
	}
	return nil
}

func (x *AnalyticsRecord_GeoData) GetLocation() *GeoData_Location {
	if x != nil {
		return x.Location
	}
	return nil
}

type AnalyticsRecord_NetworkStats struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	OpenConnections   int64 `protobuf:"varint,1,opt,name=OpenConnections,proto3" json:"OpenConnections,omitempty"`
	ClosedConnections int64 `protobuf:"varint,2,opt,name=ClosedConnections,proto3" json:"ClosedConnections,omitempty"`
	BytesIn           int64 `protobuf:"varint,3,opt,name=BytesIn,proto3" json:"BytesIn,omitempty"`
	BytesOut          int64 `protobuf:"varint,4,opt,name=BytesOut,proto3" json:"BytesOut,omitempty"`
}

func (x *AnalyticsRecord_NetworkStats) Reset() {
	*x = AnalyticsRecord_NetworkStats{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyticsRecord_NetworkStats) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyticsRecord_NetworkStats) ProtoMessage() {}

func (x *AnalyticsRecord_NetworkStats) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyticsRecord_NetworkStats.ProtoReflect.Descriptor instead.
func (*AnalyticsRecord_NetworkStats) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{5}
}

func (x *AnalyticsRecord_NetworkStats) GetOpenConnections() int64 {
	if x != nil {
		return x.OpenConnections
	}
	return 0
}

func (x *AnalyticsRecord_NetworkStats) GetClosedConnections() int64 {
	if x != nil {
		return x.ClosedConnections
	}
	return 0
}

func (x *AnalyticsRecord_NetworkStats) GetBytesIn() int64 {
	if x != nil {
		return x.BytesIn
	}
	return 0
}

func (x *AnalyticsRecord_NetworkStats) GetBytesOut() int64 {
	if x != nil {
		return x.BytesOut
	}
	return 0
}

type AnalyticsRecord struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host          string                        `protobuf:"bytes,1,opt,name=Host,proto3" json:"Host,omitempty"`
	Method        string                        `protobuf:"bytes,2,opt,name=Method,proto3" json:"Method,omitempty"`
	Path          string                        `protobuf:"bytes,3,opt,name=Path,proto3" json:"Path,omitempty"`
	RawPath       string                        `protobuf:"bytes,4,opt,name=RawPath,proto3" json:"RawPath,omitempty"`
	ContentLength int64                         `protobuf:"varint,5,opt,name=ContentLength,proto3" json:"ContentLength,omitempty"`
	UserAgent     string                        `protobuf:"bytes,6,opt,name=UserAgent,proto3" json:"UserAgent,omitempty"`
	Day           int32                         `protobuf:"varint,7,opt,name=Day,proto3" json:"Day,omitempty"`
	Month         int32                         `protobuf:"varint,8,opt,name=Month,proto3" json:"Month,omitempty"`
	Year          int32                         `protobuf:"varint,9,opt,name=Year,proto3" json:"Year,omitempty"`
	Hour          int32                         `protobuf:"varint,10,opt,name=Hour,proto3" json:"Hour,omitempty"`
	ResponseCode  int32                         `protobuf:"varint,11,opt,name=ResponseCode,proto3" json:"ResponseCode,omitempty"`
	APIKey        string                        `protobuf:"bytes,12,opt,name=APIKey,proto3" json:"APIKey,omitempty"`
	TimeStamp     *timestamp.Timestamp          `protobuf:"bytes,13,opt,name=TimeStamp,proto3" json:"TimeStamp,omitempty"`
	APIVersion    string                        `protobuf:"bytes,14,opt,name=APIVersion,proto3" json:"APIVersion,omitempty"`
	APIName       string                        `protobuf:"bytes,15,opt,name=APIName,proto3" json:"APIName,omitempty"`
	APIID         string                        `protobuf:"bytes,16,opt,name=APIID,proto3" json:"APIID,omitempty"`
	OrgID         string                        `protobuf:"bytes,17,opt,name=OrgID,proto3" json:"OrgID,omitempty"`
	RequestTime   int64                         `protobuf:"varint,18,opt,name=RequestTime,proto3" json:"RequestTime,omitempty"`
	Latency       *AnalyticsRecord_Latency      `protobuf:"bytes,19,opt,name=Latency,proto3" json:"Latency,omitempty"`
	RawRequest    string                        `protobuf:"bytes,20,opt,name=RawRequest,proto3" json:"RawRequest,omitempty"`
	RawResponse   string                        `protobuf:"bytes,21,opt,name=RawResponse,proto3" json:"RawResponse,omitempty"`
	IPAddress     string                        `protobuf:"bytes,22,opt,name=IPAddress,proto3" json:"IPAddress,omitempty"`
	Geo           *AnalyticsRecord_GeoData      `protobuf:"bytes,23,opt,name=Geo,proto3" json:"Geo,omitempty"`
	Network       *AnalyticsRecord_NetworkStats `protobuf:"bytes,24,opt,name=Network,proto3" json:"Network,omitempty"`
	Tags          []string                      `protobuf:"bytes,25,rep,name=Tags,proto3" json:"Tags,omitempty"`
	Alias         string                        `protobuf:"bytes,26,opt,name=Alias,proto3" json:"Alias,omitempty"`
	TrackPath     bool                          `protobuf:"varint,27,opt,name=TrackPath,proto3" json:"TrackPath,omitempty"`
	ExpireAt      *timestamp.Timestamp          `protobuf:"bytes,28,opt,name=ExpireAt,proto3" json:"ExpireAt,omitempty"`
}

func (x *AnalyticsRecord) Reset() {
	*x = AnalyticsRecord{}
	if protoimpl.UnsafeEnabled {
		mi := &file_gateway_proto_analytics_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AnalyticsRecord) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AnalyticsRecord) ProtoMessage() {}

func (x *AnalyticsRecord) ProtoReflect() protoreflect.Message {
	mi := &file_gateway_proto_analytics_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AnalyticsRecord.ProtoReflect.Descriptor instead.
func (*AnalyticsRecord) Descriptor() ([]byte, []int) {
	return file_gateway_proto_analytics_proto_rawDescGZIP(), []int{6}
}

func (x *AnalyticsRecord) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *AnalyticsRecord) GetMethod() string {
	if x != nil {
		return x.Method
	}
	return ""
}

func (x *AnalyticsRecord) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *AnalyticsRecord) GetRawPath() string {
	if x != nil {
		return x.RawPath
	}
	return ""
}

func (x *AnalyticsRecord) GetContentLength() int64 {
	if x != nil {
		return x.ContentLength
	}
	return 0
}

func (x *AnalyticsRecord) GetUserAgent() string {
	if x != nil {
		return x.UserAgent
	}
	return ""
}

func (x *AnalyticsRecord) GetDay() int32 {
	if x != nil {
		return x.Day
	}
	return 0
}

func (x *AnalyticsRecord) GetMonth() int32 {
	if x != nil {
		return x.Month
	}
	return 0
}

func (x *AnalyticsRecord) GetYear() int32 {
	if x != nil {
		return x.Year
	}
	return 0
}

func (x *AnalyticsRecord) GetHour() int32 {
	if x != nil {
		return x.Hour
	}
	return 0
}

func (x *AnalyticsRecord) GetResponseCode() int32 {
	if x != nil {
		return x.ResponseCode
	}
	return 0
}

func (x *AnalyticsRecord) GetAPIKey() string {
	if x != nil {
		return x.APIKey
	}
	return ""
}

func (x *AnalyticsRecord) GetTimeStamp() *timestamp.Timestamp {
	if x != nil {
		return x.TimeStamp
	}
	return nil
}

func (x *AnalyticsRecord) GetAPIVersion() string {
	if x != nil {
		return x.APIVersion
	}
	return ""
}

func (x *AnalyticsRecord) GetAPIName() string {
	if x != nil {
		return x.APIName
	}
	return ""
}

func (x *AnalyticsRecord) GetAPIID() string {
	if x != nil {
		return x.APIID
	}
	return ""
}

func (x *AnalyticsRecord) GetOrgID() string {
	if x != nil {
		return x.OrgID
	}
	return ""
}

func (x *AnalyticsRecord) GetRequestTime() int64 {
	if x != nil {
		return x.RequestTime
	}
	return 0
}

func (x *AnalyticsRecord) GetLatency() *AnalyticsRecord_Latency {
	if x != nil {
		return x.Latency
	}
	return nil
}

func (x *AnalyticsRecord) GetRawRequest() string {
	if x != nil {
		return x.RawRequest
	}
	return ""
}

func (x *AnalyticsRecord) GetRawResponse() string {
	if x != nil {
		return x.RawResponse
	}
	return ""
}

func (x *AnalyticsRecord) GetIPAddress() string {
	if x != nil {
		return x.IPAddress
	}
	return ""
}

func (x *AnalyticsRecord) GetGeo() *AnalyticsRecord_GeoData {
	if x != nil {
		return x.Geo
	}
	return nil
}

func (x *AnalyticsRecord) GetNetwork() *AnalyticsRecord_NetworkStats {
	if x != nil {
		return x.Network
	}
	return nil
}

func (x *AnalyticsRecord) GetTags() []string {
	if x != nil {
		return x.Tags
	}
	return nil
}

func (x *AnalyticsRecord) GetAlias() string {
	if x != nil {
		return x.Alias
	}
	return ""
}

func (x *AnalyticsRecord) GetTrackPath() bool {
	if x != nil {
		return x.TrackPath
	}
	return false
}

func (x *AnalyticsRecord) GetExpireAt() *timestamp.Timestamp {
	if x != nil {
		return x.ExpireAt
	}
	return nil
}

var File_gateway_proto_analytics_proto protoreflect.FileDescriptor

var file_gateway_proto_analytics_proto_rawDesc = []byte{
	0x0a, 0x1d, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x61, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x02, 0x70, 0x62, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0x4b, 0x0a, 0x17, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63,
	0x73, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x5f, 0x4c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x12,
	0x14, 0x0a, 0x05, 0x54, 0x6f, 0x74, 0x61, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x03, 0x52, 0x05,
	0x54, 0x6f, 0x74, 0x61, 0x6c, 0x12, 0x1a, 0x0a, 0x08, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61,
	0x6d, 0x22, 0x2b, 0x0a, 0x0f, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f, 0x43, 0x6f, 0x75,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x49, 0x53, 0x4f, 0x43, 0x6f, 0x64, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x49, 0x53, 0x4f, 0x43, 0x6f, 0x64, 0x65, 0x22, 0x7b,
	0x0a, 0x0c, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f, 0x43, 0x69, 0x74, 0x79, 0x12, 0x31,
	0x0a, 0x05, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e,
	0x70, 0x62, 0x2e, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f, 0x43, 0x69, 0x74, 0x79, 0x2e,
	0x4e, 0x61, 0x6d, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x4e, 0x61, 0x6d, 0x65,
	0x73, 0x1a, 0x38, 0x0a, 0x0a, 0x4e, 0x61, 0x6d, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12,
	0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65,
	0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x68, 0x0a, 0x10, 0x47,
	0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12,
	0x1a, 0x0a, 0x08, 0x4c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x01, 0x52, 0x08, 0x4c, 0x61, 0x74, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1c, 0x0a, 0x09, 0x4c,
	0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x01, 0x52, 0x09,
	0x4c, 0x6f, 0x6e, 0x67, 0x69, 0x74, 0x75, 0x64, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x54, 0x69, 0x6d,
	0x65, 0x5a, 0x6f, 0x6e, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x54, 0x69, 0x6d,
	0x65, 0x5a, 0x6f, 0x6e, 0x65, 0x22, 0xa0, 0x01, 0x0a, 0x17, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x74,
	0x69, 0x63, 0x73, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x5f, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74,
	0x61, 0x12, 0x2d, 0x0a, 0x07, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x13, 0x2e, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f,
	0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x24, 0x0a, 0x04, 0x43, 0x69, 0x74, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10,
	0x2e, 0x70, 0x62, 0x2e, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f, 0x43, 0x69, 0x74, 0x79,
	0x52, 0x04, 0x43, 0x69, 0x74, 0x79, 0x12, 0x30, 0x0a, 0x08, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x70, 0x62, 0x2e, 0x47, 0x65,
	0x6f, 0x44, 0x61, 0x74, 0x61, 0x5f, 0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x08,
	0x4c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0xac, 0x01, 0x0a, 0x1c, 0x41, 0x6e, 0x61,
	0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x5f, 0x4e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x53, 0x74, 0x61, 0x74, 0x73, 0x12, 0x28, 0x0a, 0x0f, 0x4f, 0x70, 0x65,
	0x6e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x0f, 0x4f, 0x70, 0x65, 0x6e, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x12, 0x2c, 0x0a, 0x11, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x03, 0x52, 0x11,
	0x43, 0x6c, 0x6f, 0x73, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x12, 0x18, 0x0a, 0x07, 0x42, 0x79, 0x74, 0x65, 0x73, 0x49, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x03, 0x52, 0x07, 0x42, 0x79, 0x74, 0x65, 0x73, 0x49, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x42,
	0x79, 0x74, 0x65, 0x73, 0x4f, 0x75, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x03, 0x52, 0x08, 0x42,
	0x79, 0x74, 0x65, 0x73, 0x4f, 0x75, 0x74, 0x22, 0xff, 0x06, 0x0a, 0x0f, 0x41, 0x6e, 0x61, 0x6c,
	0x79, 0x74, 0x69, 0x63, 0x73, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x48,
	0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x12,
	0x16, 0x0a, 0x06, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x06, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x50, 0x61, 0x74, 0x68, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x50, 0x61, 0x74, 0x68, 0x12, 0x18, 0x0a, 0x07, 0x52,
	0x61, 0x77, 0x50, 0x61, 0x74, 0x68, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x52, 0x61,
	0x77, 0x50, 0x61, 0x74, 0x68, 0x12, 0x24, 0x0a, 0x0d, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74,
	0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0d, 0x43, 0x6f,
	0x6e, 0x74, 0x65, 0x6e, 0x74, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x12, 0x1c, 0x0a, 0x09, 0x55,
	0x73, 0x65, 0x72, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x55, 0x73, 0x65, 0x72, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x44, 0x61, 0x79,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x44, 0x61, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x4d,
	0x6f, 0x6e, 0x74, 0x68, 0x18, 0x08, 0x20, 0x01, 0x28, 0x05, 0x52, 0x05, 0x4d, 0x6f, 0x6e, 0x74,
	0x68, 0x12, 0x12, 0x0a, 0x04, 0x59, 0x65, 0x61, 0x72, 0x18, 0x09, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x04, 0x59, 0x65, 0x61, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x6f, 0x75, 0x72, 0x18, 0x0a, 0x20,
	0x01, 0x28, 0x05, 0x52, 0x04, 0x48, 0x6f, 0x75, 0x72, 0x12, 0x22, 0x0a, 0x0c, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x0c, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x12, 0x16, 0x0a,
	0x06, 0x41, 0x50, 0x49, 0x4b, 0x65, 0x79, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x41,
	0x50, 0x49, 0x4b, 0x65, 0x79, 0x12, 0x38, 0x0a, 0x09, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x74, 0x61,
	0x6d, 0x70, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x54, 0x69, 0x6d, 0x65, 0x53, 0x74, 0x61, 0x6d, 0x70, 0x12,
	0x1e, 0x0a, 0x0a, 0x41, 0x50, 0x49, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x0e, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x41, 0x50, 0x49, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x18, 0x0a, 0x07, 0x41, 0x50, 0x49, 0x4e, 0x61, 0x6d, 0x65, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x41, 0x50, 0x49, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a, 0x05, 0x41, 0x50, 0x49,
	0x49, 0x44, 0x18, 0x10, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x41, 0x50, 0x49, 0x49, 0x44, 0x12,
	0x14, 0x0a, 0x05, 0x4f, 0x72, 0x67, 0x49, 0x44, 0x18, 0x11, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x4f, 0x72, 0x67, 0x49, 0x44, 0x12, 0x20, 0x0a, 0x0b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x54, 0x69, 0x6d, 0x65, 0x18, 0x12, 0x20, 0x01, 0x28, 0x03, 0x52, 0x0b, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x35, 0x0a, 0x07, 0x4c, 0x61, 0x74, 0x65, 0x6e,
	0x63, 0x79, 0x18, 0x13, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x70, 0x62, 0x2e, 0x41, 0x6e,
	0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64, 0x5f, 0x4c, 0x61,
	0x74, 0x65, 0x6e, 0x63, 0x79, 0x52, 0x07, 0x4c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x12, 0x1e,
	0x0a, 0x0a, 0x52, 0x61, 0x77, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x18, 0x14, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x0a, 0x52, 0x61, 0x77, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x20,
	0x0a, 0x0b, 0x52, 0x61, 0x77, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x18, 0x15, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x52, 0x61, 0x77, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x1c, 0x0a, 0x09, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x16, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x49, 0x50, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x2d,
	0x0a, 0x03, 0x47, 0x65, 0x6f, 0x18, 0x17, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x70, 0x62,
	0x2e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x52, 0x65, 0x63, 0x6f, 0x72, 0x64,
	0x5f, 0x47, 0x65, 0x6f, 0x44, 0x61, 0x74, 0x61, 0x52, 0x03, 0x47, 0x65, 0x6f, 0x12, 0x3a, 0x0a,
	0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x18, 0x18, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20,
	0x2e, 0x70, 0x62, 0x2e, 0x41, 0x6e, 0x61, 0x6c, 0x79, 0x74, 0x69, 0x63, 0x73, 0x52, 0x65, 0x63,
	0x6f, 0x72, 0x64, 0x5f, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x53, 0x74, 0x61, 0x74, 0x73,
	0x52, 0x07, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x12, 0x12, 0x0a, 0x04, 0x54, 0x61, 0x67,
	0x73, 0x18, 0x19, 0x20, 0x03, 0x28, 0x09, 0x52, 0x04, 0x54, 0x61, 0x67, 0x73, 0x12, 0x14, 0x0a,
	0x05, 0x41, 0x6c, 0x69, 0x61, 0x73, 0x18, 0x1a, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x41, 0x6c,
	0x69, 0x61, 0x73, 0x12, 0x1c, 0x0a, 0x09, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x50, 0x61, 0x74, 0x68,
	0x18, 0x1b, 0x20, 0x01, 0x28, 0x08, 0x52, 0x09, 0x54, 0x72, 0x61, 0x63, 0x6b, 0x50, 0x61, 0x74,
	0x68, 0x12, 0x36, 0x0a, 0x08, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x41, 0x74, 0x18, 0x1c, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x08, 0x45, 0x78, 0x70, 0x69, 0x72, 0x65, 0x41, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_gateway_proto_analytics_proto_rawDescOnce sync.Once
	file_gateway_proto_analytics_proto_rawDescData = file_gateway_proto_analytics_proto_rawDesc
)

func file_gateway_proto_analytics_proto_rawDescGZIP() []byte {
	file_gateway_proto_analytics_proto_rawDescOnce.Do(func() {
		file_gateway_proto_analytics_proto_rawDescData = protoimpl.X.CompressGZIP(file_gateway_proto_analytics_proto_rawDescData)
	})
	return file_gateway_proto_analytics_proto_rawDescData
}

var file_gateway_proto_analytics_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_gateway_proto_analytics_proto_goTypes = []interface{}{
	(*AnalyticsRecord_Latency)(nil),      // 0: pb.AnalyticsRecord_Latency
	(*GeoData_Country)(nil),              // 1: pb.GeoData_Country
	(*GeoData_City)(nil),                 // 2: pb.GeoData_City
	(*GeoData_Location)(nil),             // 3: pb.GeoData_Location
	(*AnalyticsRecord_GeoData)(nil),      // 4: pb.AnalyticsRecord_GeoData
	(*AnalyticsRecord_NetworkStats)(nil), // 5: pb.AnalyticsRecord_NetworkStats
	(*AnalyticsRecord)(nil),              // 6: pb.AnalyticsRecord
	nil,                                  // 7: pb.GeoData_City.NamesEntry
	(*timestamp.Timestamp)(nil),          // 8: google.protobuf.Timestamp
}
var file_gateway_proto_analytics_proto_depIdxs = []int32{
	7, // 0: pb.GeoData_City.Names:type_name -> pb.GeoData_City.NamesEntry
	1, // 1: pb.AnalyticsRecord_GeoData.Country:type_name -> pb.GeoData_Country
	2, // 2: pb.AnalyticsRecord_GeoData.City:type_name -> pb.GeoData_City
	3, // 3: pb.AnalyticsRecord_GeoData.Location:type_name -> pb.GeoData_Location
	8, // 4: pb.AnalyticsRecord.TimeStamp:type_name -> google.protobuf.Timestamp
	0, // 5: pb.AnalyticsRecord.Latency:type_name -> pb.AnalyticsRecord_Latency
	4, // 6: pb.AnalyticsRecord.Geo:type_name -> pb.AnalyticsRecord_GeoData
	5, // 7: pb.AnalyticsRecord.Network:type_name -> pb.AnalyticsRecord_NetworkStats
	8, // 8: pb.AnalyticsRecord.ExpireAt:type_name -> google.protobuf.Timestamp
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_gateway_proto_analytics_proto_init() }
func file_gateway_proto_analytics_proto_init() {
	if File_gateway_proto_analytics_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_gateway_proto_analytics_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyticsRecord_Latency); i {
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
		file_gateway_proto_analytics_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoData_Country); i {
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
		file_gateway_proto_analytics_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoData_City); i {
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
		file_gateway_proto_analytics_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeoData_Location); i {
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
		file_gateway_proto_analytics_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyticsRecord_GeoData); i {
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
		file_gateway_proto_analytics_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyticsRecord_NetworkStats); i {
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
		file_gateway_proto_analytics_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AnalyticsRecord); i {
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
			RawDescriptor: file_gateway_proto_analytics_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_gateway_proto_analytics_proto_goTypes,
		DependencyIndexes: file_gateway_proto_analytics_proto_depIdxs,
		MessageInfos:      file_gateway_proto_analytics_proto_msgTypes,
	}.Build()
	File_gateway_proto_analytics_proto = out.File
	file_gateway_proto_analytics_proto_rawDesc = nil
	file_gateway_proto_analytics_proto_goTypes = nil
	file_gateway_proto_analytics_proto_depIdxs = nil
}
