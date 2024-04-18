package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"time"

	"github.com/chancez/capper/pkg/namespaces"
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

type Config struct {
	Interface       string
	Filter          string
	Snaplen         int
	Promisc         bool
	NumPackets      uint64
	CaptureDuration time.Duration
	Netns           string
}

type PacketHandler interface {
	HandlePacket(gopacket.Packet) error
}

type PacketHandlerFunc func(gopacket.Packet) error

func (f PacketHandlerFunc) HandlePacket(p gopacket.Packet) error {
	return f(p)
}

func getInterface(log *slog.Logger, conf Config) (string, error) {
	device := conf.Interface
	if device == "" {
		log.Debug("interface not specified, using first interface")
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			return "", fmt.Errorf("error listing network interfaces: %w", err)
		}
		if len(ifaces) == 0 {
			return "", errors.New("host has no interfaces")

		}
		device = ifaces[0].Name
	}
	return device, nil
}

func Run(ctx context.Context, log *slog.Logger, conf Config, handler PacketHandler) error {
	clock := clockwork.NewRealClock()
	start := clock.Now()
	count := uint64(0)

	var handle *pcap.Handle
	var device string
	runCapture := func() error {
		var err error
		device, err = getInterface(log, conf)
		if err != nil {
			return fmt.Errorf("error getting interface: %w", err)
		}

		log.Debug("starting capture", "interface", device, "num_packets", conf.NumPackets, "duration", conf.CaptureDuration)
		handle, err = NewLiveHandle(device, conf.Filter, conf.Snaplen, conf.Promisc)
		if err != nil {
			return fmt.Errorf("error creating handle: %w", err)
		}
		return nil
	}

	if runtime.GOOS == "linux" && conf.Netns != "" {
		runCaptureOld := runCapture
		runCapture = func() error {
			return namespaces.RunInNetns(runCaptureOld, conf.Netns)
		}
	}

	err := runCapture()
	if err != nil {
		return err
	}

	defer func() {
		log.Debug("capture finished", "interface", device, "packets", count, "capture_duration", clock.Since(start))
		handle.Close()
	}()

	packetsCtx := ctx
	if conf.CaptureDuration > 0 {
		var packetsCancel context.CancelFunc
		packetsCtx, packetsCancel = context.WithTimeout(ctx, conf.CaptureDuration)
		defer packetsCancel()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.PacketsCtx(packetsCtx) {
		err := handler.HandlePacket(packet)
		if err != nil {
			return fmt.Errorf("error handling packet: %w", err)
		}
		count++
		if conf.NumPackets != 0 && count >= conf.NumPackets {
			log.Debug("reached num_packets limit, stopping capture", "num_packets", conf.NumPackets)
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
