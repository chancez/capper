package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/spf13/pflag"
)

type captureOpts struct {
	Logger        *slog.Logger
	Interfaces    []string
	Filter        string
	CaptureConfig capture.Config
	OutputFile    string
	AlwaysPrint   bool
	K8sPod        []string
	K8sNamespace  string
}

func newCaptureFlags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("capture-flags", pflag.ExitOnError)
	fs.StringSliceP("interface", "i", []string{}, "Interface(s) to capture packets on.")
	fs.IntP("snapshot-length", "s", 262144, "Configure the snaplength.")
	fs.BoolP("no-promiscuous-mode", "p", false, "Don't put the interface into promiscuous mode.")
	fs.IntP("buffer-size", "B", 0, "Set the operating system capture buffer size (in bytes).") // TODO: Should we match tcpdump which has this in units of KiB?
	fs.StringP("output-file", "w", "", "Store output into the file specified. Use '-' for stdout.")
	fs.String("output-format", "pcap", "Output pcap in the specified format. Valid options are pcap and pcapng.")
	fs.BoolP("print", "P", false, "Output the packet summary/details, even if writing raw packet data using the -o option.")
	fs.Uint64P("capture-count", "c", 0, "Number of packets to capture.")
	fs.DurationP("capture-duration", "d", 0, "Duration to capture packets.")
	fs.StringSlice("k8s-pod", nil, "Run the capture on the specified k8s pod(s). Must also set k8s-namespace.")
	fs.String("k8s-namespace", "", "Specify namespace of the pods to capture.")
	fs.String("log-level", "info", "Configure the log level.")
	return fs
}

func getCaptureOpts(ctx context.Context, filter string, fs *pflag.FlagSet) (*captureOpts, error) {
	ifaces, err := fs.GetStringSlice("interface")
	if err != nil {
		return nil, err
	}
	snaplen, err := fs.GetInt("snapshot-length")
	if err != nil {
		return nil, err
	}
	bufferSize, err := fs.GetInt("buffer-size")
	if err != nil {
		return nil, err
	}
	noPromisc, err := fs.GetBool("no-promiscuous-mode")
	if err != nil {
		return nil, err
	}
	outputFile, err := fs.GetString("output-file")
	if err != nil {
		return nil, err
	}
	outputFormat, err := fs.GetString("output-format")
	if err != nil {
		return nil, err
	}
	var format capperpb.PcapOutputFormat
	switch outputFormat {
	case "pcap":
		format = capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAP
	case "pcapng":
		format = capperpb.PcapOutputFormat_OUTPUT_FORMAT_PCAPNG
	default:
		return nil, fmt.Errorf("invalid output format: %s", outputFormat)
	}
	alwaysPrint, err := fs.GetBool("print")
	if err != nil {
		return nil, err
	}
	numPackets, err := fs.GetUint64("capture-count")
	if err != nil {
		return nil, err
	}
	dur, err := fs.GetDuration("capture-duration")
	if err != nil {
		return nil, err
	}
	k8sPod, err := fs.GetStringSlice("k8s-pod")
	if err != nil {
		return nil, err
	}
	k8sNs, err := fs.GetString("k8s-namespace")
	if err != nil {
		return nil, err
	}
	logLevel, err := fs.GetString("log-level")
	if err != nil {
		return nil, err
	}

	log, err := newLevelLogger(logLevel)
	if err != nil {
		return nil, err
	}

	return &captureOpts{
		Logger:     log,
		Interfaces: ifaces,
		Filter:     filter,
		CaptureConfig: capture.Config{
			Filter:          filter,
			Snaplen:         snaplen,
			BufferSize:      bufferSize,
			Promisc:         !noPromisc,
			NumPackets:      numPackets,
			CaptureDuration: dur,
			OutputFormat:    format,
		},
		OutputFile:   outputFile,
		AlwaysPrint:  alwaysPrint,
		K8sPod:       k8sPod,
		K8sNamespace: k8sNs,
	}, nil
}

func newSerfFlags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("serf-flags", pflag.ExitOnError)
	fs.String("node-name", "", "The node name for this peer. Defaults to the hostname if unspecified.")
	fs.StringSlice("serf-peers", []string{}, "List of serf peers.")
	fs.String("serf-listen-address", "127.0.0.1:7946", "Listen address to use for serf.")
	return fs
}

type serfOpts struct {
	NodeName   string
	Peers      []string
	ListenAddr string
}

func getSerfOpts(fs *pflag.FlagSet) (serfOpts, error) {
	nodeName, err := fs.GetString("node-name")
	if err != nil {
		return serfOpts{}, nil
	}
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}
	serfPeers, err := fs.GetStringSlice("serf-peers")
	if err != nil {
		return serfOpts{}, nil
	}
	serfListen, err := fs.GetString("serf-listen-address")
	if err != nil {
		return serfOpts{}, nil
	}
	return serfOpts{
		NodeName:   nodeName,
		Peers:      serfPeers,
		ListenAddr: serfListen,
	}, nil
}

func newRemoteFlags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("remote-flags", pflag.ExitOnError)
	fs.StringP("server", "a", "127.0.0.1:48999", "Capper address to connect to")
	fs.Duration("request-timeout", 0, "Request timeout")
	fs.Duration("connection-timeout", 10*time.Second, "Connection timeout")
	return fs
}

type remoteOpts struct {
	Address           string
	RequestTimeout    time.Duration
	ConnectionTimeout time.Duration
}

func getRemoteOpts(fs *pflag.FlagSet) (remoteOpts, error) {
	addr, err := fs.GetString("server")
	if err != nil {
		return remoteOpts{}, err
	}
	reqTimeout, err := fs.GetDuration("request-timeout")
	if err != nil {
		return remoteOpts{}, err
	}
	connTimeout, err := fs.GetDuration("connection-timeout")
	if err != nil {
		return remoteOpts{}, err
	}
	return remoteOpts{
		Address:           addr,
		RequestTimeout:    reqTimeout,
		ConnectionTimeout: connTimeout,
	}, nil
}
