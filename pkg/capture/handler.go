package capture

import (
	"fmt"
	"io"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type PacketHandler interface {
	HandlePacket(gopacket.Packet) error
}

type PacketHandlerFunc func(gopacket.Packet) error

func (f PacketHandlerFunc) HandlePacket(p gopacket.Packet) error {
	return f(p)
}

type PacketWriterHandler struct {
	pcapWriter    *pcapgo.Writer
	headerWritten bool
	snaplen       uint32
	linkType      layers.LinkType
}

func NewPacketWriterHandler(w io.Writer, snaplen uint32, linkType layers.LinkType) *PacketWriterHandler {
	return &PacketWriterHandler{
		pcapWriter: pcapgo.NewWriter(w),
		snaplen:    snaplen,
		linkType:   linkType,
	}
}

func (pwh *PacketWriterHandler) HandlePacket(p gopacket.Packet) error {
	if !pwh.headerWritten {
		if err := pwh.pcapWriter.WriteFileHeader(pwh.snaplen, pwh.linkType); err != nil {
			return fmt.Errorf("error writing file header: %w", err)
		}
		pwh.headerWritten = true
	}

	if err := pwh.pcapWriter.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil {
		return fmt.Errorf("error writing packet: %w", err)
	}
	return nil
}

var PacketPrinterHandler = PacketHandlerFunc(func(p gopacket.Packet) error {
	fmt.Println(p)
	return nil
})

func ChainPacketHandlers(handlers ...PacketHandler) PacketHandler {
	return PacketHandlerFunc(func(p gopacket.Packet) error {
		for _, handler := range handlers {
			err := handler.HandlePacket(p)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
