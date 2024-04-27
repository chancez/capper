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

type PcapWriterHandler struct {
	pcapWriter *pcapgo.Writer
	snaplen    uint32
}

func NewPcapWriterHandler(w io.Writer, linkType layers.LinkType, snaplen uint32) (*PcapWriterHandler, error) {
	pcapWriter := pcapgo.NewWriter(w)
	if err := pcapWriter.WriteFileHeader(snaplen, linkType); err != nil {
		return nil, fmt.Errorf("error writing file header: %w", err)
	}

	return &PcapWriterHandler{
		pcapWriter: pcapWriter,
		snaplen:    snaplen,
	}, nil
}

func (pwh *PcapWriterHandler) HandlePacket(p gopacket.Packet) error {
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
