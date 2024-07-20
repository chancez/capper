package capture

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"

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
}

func ngInterfaceDescription(iface CaptureInterface) string {
	b, _ := json.Marshal(iface)
	return string(b)
}

func newNgInterface(iface CaptureInterface, linkType layers.LinkType) pcapgo.NgInterface {
	return pcapgo.NgInterface{
		Name:        iface.Name,
		Index:       iface.Index,
		LinkType:    linkType,
		Description: ngInterfaceDescription(iface),
	}
}

func newNgWriterOptions(arch, os string) pcapgo.NgWriterOptions {
	return pcapgo.NgWriterOptions{
		SectionInfo: pcapgo.NgSectionInfo{
			Hardware:    arch,
			OS:          os,
			Application: "capper",
		},
	}
}

func NewPcapNgWriterHandler(w io.Writer, linkType layers.LinkType, snaplen uint32, ifaces []CaptureInterface) (*PcapNgWriterHandler, error) {
	// TODO: This needs to be a parameter for remote captures to avoid using the local arch/OS
	options := newNgWriterOptions(runtime.GOARCH, runtime.GOOS)
	iface := ifaces[0]
	intf := newNgInterface(iface, linkType)
	pcapngWriter, err := pcapgo.NewNgWriterInterface(w, intf, options)
	if err != nil {
		return nil, fmt.Errorf("error creating pcapng writer: %w", err)
	}

	for _, iface := range ifaces[1:] {
		intf := newNgInterface(iface, linkType)
		_, err := pcapngWriter.AddInterface(intf)
		if err != nil {
			return nil, err
		}
	}

	return &PcapNgWriterHandler{
		pcapngWriter: pcapngWriter,
		snaplen:      snaplen,
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
