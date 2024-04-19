package cmd

import (
	"context"
	"log/slog"

	"github.com/chancez/capper/pkg/capture"
	"github.com/spf13/pflag"
)

type captureOpts struct {
	Logger        *slog.Logger
	Interfaces    []string
	Filter        string
	CaptureConfig capture.Config
	OutputFile    string
	AlwaysPrint   bool
	K8sPod        string
	K8sNamespace  string
}

func newCaptureFlags() *pflag.FlagSet {
	fs := pflag.NewFlagSet("capture-flags", pflag.ExitOnError)
	fs.StringSliceP("interface", "i", []string{}, "Interface(s) to capture packets on.")
	fs.IntP("snaplen", "s", 262144, "Configure the snaplength.")
	fs.BoolP("no-promiscuous-mode", "p", false, "Don't put the interface into promiscuous mode.")
	fs.StringP("output", "o", "", "Store output into the file specified.")
	fs.BoolP("print", "P", false, "Output the packet summary/details, even if writing raw packet data using the -o option.")
	fs.Uint64P("num-packets", "n", 0, "Number of packets to capture.")
	fs.DurationP("duration", "d", 0, "Duration to capture packets.")
	fs.StringP("netns", "N", "", "Run the capture in the specified network namespace")
	fs.String("k8s-pod", "", "Run the capture on the target k8s pod. Requires containerd. Must also set k8s-namespace.")
	fs.String("k8s-namespace", "", "Run the capture on the target k8s pod in namespace. Requires containerd. Must also set k8s-pod.")
	fs.String("log-level", "info", "Configure the log level.")
	return fs
}

func getCaptureOpts(ctx context.Context, filter string, fs *pflag.FlagSet) (*captureOpts, error) {
	ifaces, err := fs.GetStringSlice("interface")
	if err != nil {
		return nil, err
	}
	snaplen, err := fs.GetInt("snaplen")
	if err != nil {
		return nil, err
	}
	noPromisc, err := fs.GetBool("no-promiscuous-mode")
	if err != nil {
		return nil, err
	}
	outputFile, err := fs.GetString("output")
	if err != nil {
		return nil, err
	}
	alwaysPrint, err := fs.GetBool("print")
	if err != nil {
		return nil, err
	}
	numPackets, err := fs.GetUint64("num-packets")
	if err != nil {
		return nil, err
	}
	dur, err := fs.GetDuration("duration")
	if err != nil {
		return nil, err
	}
	netns, err := fs.GetString("netns")
	if err != nil {
		return nil, err
	}
	k8sPod, err := fs.GetString("k8s-pod")
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
			Promisc:         !noPromisc,
			NumPackets:      numPackets,
			CaptureDuration: dur,
			Netns:           netns,
		},
		OutputFile:   outputFile,
		AlwaysPrint:  alwaysPrint,
		K8sPod:       k8sPod,
		K8sNamespace: k8sNs,
	}, nil
}
