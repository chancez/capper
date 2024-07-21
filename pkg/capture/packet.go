package capture

import (
	"time"

	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
)

type TimestampedPacket interface {
	Timestamp() time.Time
}

var _ TimestampedPacket = (*GoPacketWrapper)(nil)
var _ TimestampedPacket = (*CapperPacketWrapper)(nil)

type GoPacketWrapper struct {
	gopacket.Packet
}

func (p *GoPacketWrapper) Timestamp() time.Time {
	return p.Metadata().Timestamp
}

type CapperPacketWrapper struct {
	*capperpb.Packet
}

func (p *CapperPacketWrapper) Timestamp() time.Time {
	return p.Metadata.CaptureInfo.Timestamp.AsTime()
}
