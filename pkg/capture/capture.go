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

func newLiveHandle(iface string, filter string, snaplen int, promisc bool, bufferSize int) (*pcap.Handle, error) {
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

func NewLiveHandle(iface string, netns string, filter string, snaplen int, promisc bool, bufferSize int) (*pcap.Handle, error) {
	runCapture := func() (*pcap.Handle, error) {
		var err error
		handle, err := newLiveHandle(iface, filter, snaplen, promisc, bufferSize)
		if err != nil {
			return nil, err
		}
		return handle, nil
	}

	if runtime.GOOS == "linux" && netns != "" {
		runCaptureOld := runCapture
		runCapture = func() (*pcap.Handle, error) {
			var handle *pcap.Handle
			err := namespaces.RunInNetns(func() error {
				var err error
				handle, err = runCaptureOld()
				return err
			}, netns)
			return handle, err
		}
	}
	return runCapture()
}

type Config struct {
	Filter          string
	Snaplen         int
	Promisc         bool
	NumPackets      uint64
	CaptureDuration time.Duration
	BufferSize      int
}

func getInterface(netns string) (string, error) {
	runGetIface := func() (string, error) {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			return "", fmt.Errorf("error listing network interfaces: %w", err)
		}
		if len(ifaces) == 0 {
			return "", errors.New("host has no interfaces")

		}
		return ifaces[0].Name, nil
	}
	if runtime.GOOS == "linux" && netns != "" {
		oldGetIface := runGetIface
		runGetIface = func() (string, error) {
			var iface string
			err := namespaces.RunInNetns(func() error {
				innerIface, innerErr := oldGetIface()
				iface = innerIface
				return innerErr
			}, netns)
			return iface, err
		}
	}
	return runGetIface()
}

type Capture interface {
	LinkType() layers.LinkType
	Start(ctx context.Context, handler PacketHandler) error
	Interfaces() []string
	Close()
}

type BasicCapture struct {
	log   *slog.Logger
	clock clockwork.Clock
	conf  Config

	iface  string
	handle *pcap.Handle
}

func NewBasic(ctx context.Context, log *slog.Logger, iface, netns string, conf Config) (*BasicCapture, error) {
	clock := clockwork.NewRealClock()

	if iface == "" {
		var err error
		iface, err = getInterface(netns)
		if err != nil {
			return nil, fmt.Errorf("error getting interface: %w", err)
		}
	}

	handle, err := NewLiveHandle(iface, netns, conf.Filter, conf.Snaplen, conf.Promisc, conf.BufferSize)
	if err != nil {
		return nil, fmt.Errorf("error creating handle: %w", err)
	}

	return &BasicCapture{
		log:    log,
		clock:  clock,
		conf:   conf,
		iface:  iface,
		handle: handle,
	}, nil
}

func (c *BasicCapture) LinkType() layers.LinkType {
	return c.handle.LinkType()
}

func (c *BasicCapture) Interfaces() []string {
	return []string{c.iface}
}

func (c *BasicCapture) Start(ctx context.Context, handler PacketHandler) error {
	start := c.clock.Now()
	count := uint64(0)

	c.log.Info("capture started", "interface", c.iface, "link_type", c.handle.LinkType(), "snaplen", c.conf.Snaplen, "promisc", c.conf.Promisc, "num_packets", c.conf.NumPackets, "duration", c.conf.CaptureDuration)
	defer func() {
		logFields := []any{"interface", c.iface, "packets", count, "capture_duration", c.clock.Since(start)}
		stats, err := c.handle.Stats()
		if err != nil {
			c.log.Error("unable to get capture stats", "interface", c.iface, "error", err)
		} else {
			logFields = append(logFields, "packets_dropped", stats.PacketsDropped, "packets_received", stats.PacketsReceived)
		}
		c.log.Info("capture finished", logFields...)
	}()

	packetsCtx := ctx
	if c.conf.CaptureDuration > 0 {
		var packetsCancel context.CancelFunc
		packetsCtx, packetsCancel = context.WithTimeout(ctx, c.conf.CaptureDuration)
		defer packetsCancel()
	}

	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	for packet := range packetSource.PacketsCtx(packetsCtx) {
		err := handler.HandlePacket(packet)
		if err != nil {
			return fmt.Errorf("error handling packet: %w", err)
		}
		count++
		if c.conf.NumPackets != 0 && count >= c.conf.NumPackets {
			c.log.Debug("reached num_packets limit, stopping capture", "num_packets", c.conf.NumPackets)
			break
		}
	}
	return nil
}

func (c *BasicCapture) Close() {
	c.handle.Close()
}
