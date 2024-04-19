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
	"github.com/gopacket/gopacket/layers"
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
		log.Info("capture finished", "interface", iface, "packets", count, "capture_duration", clock.Since(start))
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

func Multi(ctx context.Context, log *slog.Logger, ifaces []string, conf Config, handler PacketHandler) error {
	// If we don't have multiple interfaces, just delegate to Run()
	if len(ifaces) < 2 {
		// Run() handles empty iface by picking one automatically if it's not specified.
		iface := ""
		if len(ifaces) == 1 {
			iface = ifaces[0]
		}
		return Start(ctx, log, iface, conf, handler)
	}
	clock := clockwork.NewRealClock()

	runCapture := func(iface string) (*pcap.Handle, error) {
		var err error
		handle, err := NewLiveHandle(iface, conf.Filter, conf.Snaplen, conf.Promisc, conf.BufferSize)
		if err != nil {
			return nil, fmt.Errorf("error creating handle: %w", err)
		}
		return handle, nil
	}

	if runtime.GOOS == "linux" && conf.Netns != "" {
		runCaptureOld := runCapture
		runCapture = func(iface string) (*pcap.Handle, error) {
			var handle *pcap.Handle
			err := namespaces.RunInNetns(func() error {
				var err error
				handle, err = runCaptureOld(iface)
				return err
			}, conf.Netns)
			return handle, err
		}
	}

	outerStart := clock.Now()
	outerCount := uint64(0)

	var sources []NamedPacketSource
	// We will get the linkType from the first handle, and use that for the
	// handler provided.
	var handlerLinkType layers.LinkType

	log.Debug("starting sub-captures", "interfaces", ifaces)
	for _, iface := range ifaces {
		start := clock.Now()
		// TODO: Count packets for the sub-captures.

		handle, err := runCapture(iface)
		if err != nil {
			return err
		}
		log.Debug("sub-capture started", "interface", iface, "link_type", handle.LinkType(), "num_packets", conf.NumPackets, "duration", conf.CaptureDuration)

		// Set the linkType for our PacketHandler to the linkType of the first
		// handle
		if handlerLinkType == layers.LinkTypeNull {
			handlerLinkType = handle.LinkType()
			log.Debug("using first handles linkType", "link_type", handlerLinkType)
		}

		sources = append(sources, NamedPacketSource{
			Name: "iface-" + iface,
			// We use the original handle LinkType in the PacketSource
			PacketSource: gopacket.NewPacketSource(handle, handle.LinkType()),
		})

		defer func() {
			log.Debug("sub-capture finished", "interface", iface, "capture_duration", clock.Since(start))
			handle.Close()
		}()
	}

	log.Info("multi capture started", "interfaces", ifaces, "link_type", handlerLinkType)
	defer log.Info("multi capture finished", "interfaces", ifaces, "packets", outerCount, "capture_duration", clock.Since(outerStart))

	packetsCtx := ctx
	if conf.CaptureDuration > 0 {
		var packetsCancel context.CancelFunc
		packetsCtx, packetsCancel = context.WithTimeout(ctx, conf.CaptureDuration)
		defer packetsCancel()
	}

	// Drain at 10 packets, or NumPackets if it's lower than 10
	heapDrainThreshold := 10
	if conf.NumPackets > 0 && conf.NumPackets < uint64(heapDrainThreshold) {
		heapDrainThreshold = int(conf.NumPackets)
	}
	flushInterval := 2 * time.Second
	// Scale the merge buffer based on the number of captures
	mergeBufferSize := 10 * len(sources)
	merger := NewPacketMerger(log, sources, heapDrainThreshold, flushInterval, mergeBufferSize, 0)
	for packet := range merger.PacketsCtx(packetsCtx) {
		if err := handler.HandlePacket(handlerLinkType, packet); err != nil {
			return err
		}
		outerCount++
		if conf.NumPackets != 0 && outerCount >= conf.NumPackets {
			log.Debug("reached num_packets limit, stopping capture", "num_packets", conf.NumPackets)
			break
		}
	}
	return nil
}
