package capture

import (
	"errors"
	"fmt"
	"io"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type PacketHandler interface {
	HandlePacket(gopacket.Packet) error
	Flush() error
}

type PacketHandlerFunc func(gopacket.Packet) error

func (f PacketHandlerFunc) HandlePacket(p gopacket.Packet) error {
	return f(p)
}

func (f PacketHandlerFunc) Flush() error {
	return nil
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

func (pwh *PcapWriterHandler) Flush() error {
	return nil
}

type PcapNgWriterHandler struct {
	pcapngWriter *pcapgo.NgWriter
	snaplen      uint32
	ifaceToID    map[CaptureInterface]int
}

func NewPcapNgWriterHandler(w io.Writer, linkType layers.LinkType, snaplen uint32, ifaces []CaptureInterface) (*PcapNgWriterHandler, error) {
	intf := pcapgo.NgInterface{
		Name:     ifaces[0].Name,
		Index:    ifaces[0].Index,
		LinkType: linkType,
	}
	pcapngWriter, err := pcapgo.NewNgWriterInterface(w, intf, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return nil, fmt.Errorf("error creating pcapng writer: %w", err)
	}
	ifaceToID := make(map[CaptureInterface]int)
	ifaceToID[ifaces[0]] = 0

	for _, iface := range ifaces[1:] {
		intf := pcapgo.NgInterface{
			Name:     iface.Name,
			Index:    iface.Index,
			LinkType: linkType,
		}
		id, err := pcapngWriter.AddInterface(intf)
		if err != nil {
			return nil, err
		}
		ifaceToID[iface] = id
	}

	return &PcapNgWriterHandler{
		pcapngWriter: pcapngWriter,
		snaplen:      snaplen,
		ifaceToID:    ifaceToID,
	}, nil
}

func (pwh *PcapNgWriterHandler) HandlePacket(p gopacket.Packet) error {
	if err := pwh.pcapngWriter.WritePacket(p.Metadata().CaptureInfo, p.Data()); err != nil {
		return fmt.Errorf("error writing packet: %w", err)
	}
	return nil
}

func (pwh *PcapNgWriterHandler) Flush() error {
	return pwh.pcapngWriter.Flush()
}

var PacketPrinterHandler = PacketHandlerFunc(func(p gopacket.Packet) error {
	fmt.Println(p)
	return nil
})

type ChainPacketHandler struct {
	handlers []PacketHandler
}

func (chain *ChainPacketHandler) HandlePacket(p gopacket.Packet) error {
	for _, handler := range chain.handlers {
		err := handler.HandlePacket(p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (chain *ChainPacketHandler) Flush() error {
	var err error
	for _, handler := range chain.handlers {
		err = errors.Join(err, handler.Flush())
	}
	return err
}

func ChainPacketHandlers(handlers ...PacketHandler) PacketHandler {
	return &ChainPacketHandler{handlers: handlers}
}
