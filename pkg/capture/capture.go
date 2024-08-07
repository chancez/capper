package capture

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"time"

	containerdutil "github.com/chancez/capper/pkg/containerd"
	"github.com/chancez/capper/pkg/namespaces"
	capperpb "github.com/chancez/capper/proto/capper"
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
			err := namespaces.RunInNetns(func(nsInode uint64) error {
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
	OutputFormat    capperpb.PcapOutputFormat
}

type CaptureInterface struct {
	Name            string
	Index           int
	Hostname        string
	NetnsInode      uint64
	Netns           string
	LinkType        layers.LinkType
	K8sPod          string
	K8sPodNamespace string
}

func getInterface(ifaceName string, netns string) (CaptureInterface, error) {
	runGetIface := func() (CaptureInterface, error) {
		ifaces, err := pcap.FindAllDevs()
		if err != nil {
			return CaptureInterface{}, fmt.Errorf("error listing network interfaces: %w", err)
		}
		if len(ifaces) == 0 {
			return CaptureInterface{}, errors.New("host has no interfaces")
		}
		var selected pcap.Interface
		if ifaceName != "" {
			for _, iface := range ifaces {
				if iface.Name == ifaceName {
					selected = iface
					break
				}
			}
		} else {
			selected = ifaces[0]
		}
		if selected.Name == "" {
			return CaptureInterface{}, fmt.Errorf("unable to find interface %s", ifaceName)
		}

		netIface, err := net.InterfaceByName(selected.Name)
		if err != nil {
			return CaptureInterface{}, fmt.Errorf("error getting iface: %w", err)
		}

		hostname, err := os.Hostname()
		if err != nil {
			return CaptureInterface{}, fmt.Errorf("error getting hostname for iface: %w", err)
		}

		return CaptureInterface{
			Name:     selected.Name,
			Index:    netIface.Index,
			Hostname: hostname,
		}, nil
	}
	if runtime.GOOS == "linux" && netns != "" {
		oldGetIface := runGetIface
		runGetIface = func() (CaptureInterface, error) {
			var iface CaptureInterface
			err := namespaces.RunInNetns(func(nsInode uint64) error {
				innerIface, innerErr := oldGetIface()
				iface = innerIface
				iface.NetnsInode = nsInode
				iface.Netns = netns
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
	Close()
}

type BasicCapture struct {
	log   *slog.Logger
	clock clockwork.Clock
	conf  Config

	iface  CaptureInterface
	handle *pcap.Handle
}

func NewBasic(ctx context.Context, log *slog.Logger, ifaceName string, netns string, conf Config) (*BasicCapture, error) {
	pod := &containerdutil.Pod{Netns: netns}
	return newCapture(ctx, log, ifaceName, pod, conf)
}

func NewContainer(ctx context.Context, log *slog.Logger, ifaceName string, pod *containerdutil.Pod, conf Config) (*BasicCapture, error) {
	return newCapture(ctx, log, ifaceName, pod, conf)
}

func newCapture(ctx context.Context, log *slog.Logger, ifaceName string, pod *containerdutil.Pod, conf Config) (*BasicCapture, error) {
	clock := clockwork.NewRealClock()

	netns := ""
	if pod != nil {
		netns = pod.Netns
	}
	iface, err := getInterface(ifaceName, netns)
	if err != nil {
		return nil, fmt.Errorf("error getting interface: %w", err)
	}
	iface.K8sPod = pod.Name
	iface.K8sPodNamespace = pod.Namespace

	handle, err := NewLiveHandle(iface.Name, netns, conf.Filter, conf.Snaplen, conf.Promisc, conf.BufferSize)
	if err != nil {
		return nil, fmt.Errorf("error creating handle: %w", err)
	}

	iface.LinkType = handle.LinkType()

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

func (c *BasicCapture) Interface() CaptureInterface {
	return c.iface
}

func (c *BasicCapture) Start(ctx context.Context, handler PacketHandler) error {
	start := c.clock.Now()
	count := uint64(0)

	c.log.Info("capture started", "interface", c.iface, "link_type", c.handle.LinkType(), "snaplen", c.conf.Snaplen, "promisc", c.conf.Promisc, "num_packets", c.conf.NumPackets, "duration", c.conf.CaptureDuration)
	defer func() {
		err := handler.Flush()
		if err != nil {
			c.log.Error("error flushing handler", "interface", c.iface, "error", err)
		}
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
		packet.Metadata().AncillaryData = append(packet.Metadata().AncillaryData, &capperpb.AncillaryPacketData{
			LinkType:        int64(c.iface.LinkType),
			NodeName:        c.iface.Hostname,
			Netns:           c.iface.Netns,
			NetnsInode:      c.iface.NetnsInode,
			IfaceName:       c.iface.Name,
			Hardware:        runtime.GOARCH,
			OperatingSystem: runtime.GOOS,
			K8SPodName:      c.iface.K8sPod,
			K8SPodNamespace: c.iface.K8sPodNamespace,
		})
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
