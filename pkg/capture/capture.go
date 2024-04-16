package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jonboulle/clockwork"
)

func NewLiveHandle(device string, filter string, snaplen int, promisc bool) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	if err := inactive.SetSnapLen(snaplen); err != nil {
		return nil, fmt.Errorf("error setting snaplen on handle: %w", err)
	}

	if err := inactive.SetPromisc(promisc); err != nil {
		return nil, fmt.Errorf("error setting promiscuous mode on handle: %w", err)
	}

	if err := inactive.SetTimeout(time.Second); err != nil {
		return nil, fmt.Errorf("error setting timeout on handle: %w", err)
	}

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("error activating handle: %w", err)
	}

	if filter != "" {
		if err := handle.SetBPFFilter(filter); err != nil {
			return nil, fmt.Errorf("error setting filter on handle: %w", err)
		}
	}
	return handle, nil
}

type PacketCapture struct {
	clock   clockwork.Clock
	log     *slog.Logger
	handler PacketHandler
}

type PacketHandler interface {
	HandlePacket(gopacket.Packet) error
}

type PacketHandlerFunc func(gopacket.Packet) error

func (f PacketHandlerFunc) HandlePacket(p gopacket.Packet) error {
	return f(p)
}

func New(log *slog.Logger, handler PacketHandler) *PacketCapture {
	return &PacketCapture{
		clock:   clockwork.NewRealClock(),
		log:     log,
		handler: handler,
	}
}

func (c *PacketCapture) Run(ctx context.Context, device string, filter string, snaplen int, promisc bool, numPackets uint64, captureDuration time.Duration) error {
	if device == "" {
		c.log.Debug("interface not specified, using first interface")
		ifaces, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("error listing network interfaces: %w", err)
		}
		if len(ifaces) == 0 {
			return errors.New("host has no interfaces")

		}
		device = ifaces[0].Name
	}

	start := c.clock.Now()
	count := uint64(0)
	c.log.Debug("starting capture", "interface", device, "num_packets", numPackets, "duration", captureDuration)

	handle, err := NewLiveHandle(device, filter, snaplen, promisc)
	if err != nil {
		return fmt.Errorf("error creating handle: %w", err)
	}
	defer func() {
		c.log.Debug("capture finished", "interface", device, "packets", count, "capture_duration", c.clock.Since(start))
		handle.Close()
	}()

	packetsCtx := ctx
	if captureDuration > 0 {
		var packetsCancel context.CancelFunc
		packetsCtx, packetsCancel = context.WithTimeout(ctx, captureDuration)
		defer packetsCancel()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.PacketsCtx(packetsCtx) {
		err := c.handler.HandlePacket(packet)
		if err != nil {
			return fmt.Errorf("error handling packet: %w", err)
		}
		count++
		if numPackets != 0 && count >= numPackets {
			c.log.Debug("reached num_packets limit, stopping capture", "num_packets", numPackets)
			break
		}
	}
	return nil
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

func Local(ctx context.Context, device string, filter string, snaplen int, promisc bool, outputFile string, alwaysPrint bool, numPackets uint64, captureDuration time.Duration) error {
	var handlers []PacketHandler
	if alwaysPrint || outputFile == "" {
		handlers = append(handlers, PacketPrinterHandler)
	}
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("error opening output: %w", err)
		}
		defer f.Close()
		writeHandler := NewPacketWriterHandler(f, uint32(snaplen), layers.LinkTypeEthernet)
		handlers = append(handlers, writeHandler)
	}
	handler := ChainPacketHandlers(handlers...)
	pcap := New(slog.Default(), handler)
	err := pcap.Run(ctx, device, filter, snaplen, promisc, numPackets, captureDuration)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}
	return nil
}
