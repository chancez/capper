package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/chancez/capper/pkg/namespaces"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jonboulle/clockwork"
)

func NewLiveHandle(iface string, filter string, snaplen int, promisc bool, bufferSize int) (*pcap.Handle, error) {
	inactive, err := pcap.NewInactiveHandle(iface)
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

	if bufferSize > 0 {
		if err := inactive.SetBufferSize(bufferSize); err != nil {
			return nil, fmt.Errorf("error setting buffer size on handle: %w", err)
		}
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
	Filter          string
	Snaplen         int
	Promisc         bool
	NumPackets      uint64
	CaptureDuration time.Duration
	Netns           string
	BufferSize      int
}

func getInterface() (string, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("error listing network interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return "", errors.New("host has no interfaces")

	}
	return ifaces[0].Name, nil
}

// Start a packet capture on the specified interface, calling handler on each packet captured.
func Start(ctx context.Context, log *slog.Logger, iface string, conf Config, handler PacketHandler) error {
	clock := clockwork.NewRealClock()
	start := clock.Now()
	count := uint64(0)

	var handle *pcap.Handle
	runCapture := func() error {
		var err error
		if iface == "" {
			log.Debug("interface not specified, using first interface")
			iface, err = getInterface()
			if err != nil {
				return fmt.Errorf("error getting interface: %w", err)
			}
		}

		handle, err = NewLiveHandle(iface, conf.Filter, conf.Snaplen, conf.Promisc, conf.BufferSize)
		if err != nil {
			return fmt.Errorf("error creating handle: %w", err)
		}
		log.Info("capture started", "interface", iface, "link_type", handle.LinkType(), "snaplen", conf.Snaplen, "promisc", conf.Promisc, "num_packets", conf.NumPackets, "duration", conf.CaptureDuration)
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
		logFields := []any{"interface", iface, "packets", count, "capture_duration", clock.Since(start)}
		stats, err := handle.Stats()
		if err != nil {
			log.Error("unable to get capture stats", "interface", iface, "error", err)
		} else {
			logFields = append(logFields, "packets_dropped", stats.PacketsDropped, "packets_received", stats.PacketsReceived)
		}
		log.Info("capture finished", logFields...)
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
		err := handler.HandlePacket(handle.LinkType(), packet)
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
