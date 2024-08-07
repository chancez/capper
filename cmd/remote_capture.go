package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"

	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/durationpb"
)

var remoteCaptureCmd = &cobra.Command{
	Use:   "remote-capture [filter]",
	Short: "Capture packets remotely",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRemoteCapture,
}

func init() {
	rootCmd.AddCommand(remoteCaptureCmd)

	for _, fs := range []*pflag.FlagSet{
		newCaptureFlags(),
		newRemoteFlags(),
	} {
		remoteCaptureCmd.Flags().AddFlagSet(fs)
	}
}

func runRemoteCapture(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	var filter string
	if len(args) == 1 {
		filter = args[0]
	}

	remoteOpts, err := getRemoteOpts(cmd.Flags())
	if err != nil {
		return err
	}

	captureOpts, err := getCaptureOpts(ctx, filter, cmd.Flags())
	if err != nil {
		return err
	}

	if len(captureOpts.K8sPod) > 1 {
		return errors.New("remote-capture only supports a single pod filter")
	}
	var podName string
	if len(captureOpts.K8sPod) == 1 {
		podName = captureOpts.K8sPod[0]
	}

	var pod *capperpb.Pod
	if len(captureOpts.K8sPod) != 0 {
		if captureOpts.K8sNamespace == "" {
			captureOpts.K8sNamespace = "default"
		}
		pod = &capperpb.Pod{
			Namespace: captureOpts.K8sNamespace,
			Name:      podName,
		}
	}
	req := &capperpb.CaptureRequest{
		Interface:         captureOpts.Interfaces,
		Filter:            captureOpts.Filter,
		Snaplen:           int64(captureOpts.CaptureConfig.Snaplen),
		NumPackets:        captureOpts.CaptureConfig.NumPackets,
		Duration:          durationpb.New(captureOpts.CaptureConfig.CaptureDuration),
		K8SPodFilter:      pod,
		NoPromiscuousMode: !captureOpts.CaptureConfig.Promisc,
		BufferSize:        int64(captureOpts.CaptureConfig.BufferSize),
	}
	return remoteCapture(ctx, captureOpts.Logger, remoteOpts, req, captureOpts.OutputFile, captureOpts.AlwaysPrint, captureOpts.CaptureConfig.OutputFormat)
}

func remoteCapture(ctx context.Context, log *slog.Logger, remoteOpts remoteOpts, req *capperpb.CaptureRequest, outputPath string, alwaysPrint bool, outputFormat capperpb.PcapOutputFormat) error {
	var isDir bool
	if outputPath != "" {
		fi, err := os.Stat(outputPath)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && fi.IsDir() {
			isDir = true
		}
	}
	printPackets := outputPath == "" || alwaysPrint

	clock := clockwork.NewRealClock()
	log.Debug("connecting to server", "server", remoteOpts.Address)
	connCtx := ctx
	connCancel := func() {}
	if remoteOpts.ConnectionTimeout != 0 {
		connCtx, connCancel = context.WithTimeout(ctx, remoteOpts.ConnectionTimeout)
	}
	conn, err := grpc.DialContext(connCtx, remoteOpts.Address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	connCancel()
	if err != nil {
		return fmt.Errorf("error connecting to server: %w", err)
	}
	defer conn.Close()
	c := capperpb.NewCapperClient(conn)

	reqCtx := ctx
	var reqCancel context.CancelFunc
	if remoteOpts.RequestTimeout != 0 {
		reqCtx, reqCancel = context.WithTimeout(ctx, remoteOpts.RequestTimeout)
		defer reqCancel()
	}

	log.Debug("creating capture stream")
	stream, err := c.Capture(reqCtx, req)
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	handle, err := newCaptureStreamHandle(log, clock, req, stream)
	if err != nil {
		return fmt.Errorf("error creating capture: %w", err)
	}
	defer handle.Close()
	linkType := handle.LinkType()

	handler := newCommonOutputHandler(linkType, uint32(req.GetSnaplen()), printPackets, outputPath, isDir, outputFormat)
	defer handler.Flush()

	err = handle.Start(ctx, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}

	return nil
}
