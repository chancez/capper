package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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
		OutputFormat:      captureOpts.CaptureConfig.OutputFormat,
	}
	return remoteCapture(ctx, captureOpts.Logger, remoteOpts, req, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

func remoteCapture(ctx context.Context, log *slog.Logger, remoteOpts remoteOpts, req *capperpb.CaptureRequest, outputFile string, alwaysPrint bool) error {
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

	start := clock.Now()
	packetsTotal := 0

	log.Debug("creating capture stream")
	stream, err := c.Capture(reqCtx, req)
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	log.Info("capture started")
	defer func() {
		log.Info("capture finished", "packets", packetsTotal, "capture_duration", clock.Since(start))
	}()

	streamSource, err := newCaptureStreamPacketSource(stream)
	if err != nil {
		return fmt.Errorf("error creating capture stream packet source: %w", err)
	}
	linkType := streamSource.LinkType()

	var handlers []capture.PacketHandler
	if alwaysPrint || outputFile == "" {
		handlers = append(handlers, capture.PacketPrinterHandler)
	}
	if outputFile != "" {
		var w io.Writer
		if outputFile == "-" {
			w = os.Stdout
		} else {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			w = f
			defer f.Close()
		}

		writeHandler, err := capture.NewPcapWriterHandler(w, linkType, uint32(req.GetSnaplen()))
		if err != nil {
			return err
		}
		handlers = append(handlers, writeHandler)
	}
	counterHandler := capture.PacketHandlerFunc(func(gopacket.Packet) error {
		packetsTotal++
		return nil
	})
	handlers = append(handlers, counterHandler)
	handler := capture.ChainPacketHandlers(handlers...)

	packetSource := gopacket.NewPacketSource(streamSource, linkType)
	packetsCh := packetSource.PacketsCtx(ctx)

	for packet := range packetsCh {
		if err := handler.HandlePacket(packet); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}

	return nil
}

type captureStreamPacketSource struct {
	stream capperpb.Capper_CaptureClient

	resp     *capperpb.CaptureResponse
	linkType layers.LinkType
}

func newCaptureStreamPacketSource(stream capperpb.Capper_CaptureClient) (*captureStreamPacketSource, error) {
	resp, err := stream.Recv()
	if status.Code(err) == codes.Canceled || err == io.EOF {
		return nil, fmt.Errorf("stream completed during initialization: %w", err)
	}
	if err != nil {
		return nil, err
	}

	linkType := layers.LinkType(resp.GetPacket().GetMetadata().GetCaptureInfo().GetAncillaryData().GetLinkType())
	return &captureStreamPacketSource{stream: stream, resp: resp, linkType: linkType}, nil
}

func (cs *captureStreamPacketSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	var err error
	// use the cached response from initialization, otherwise query the stream for the next response
	resp := cs.resp
	if cs.resp == nil {
		resp, err = cs.stream.Recv()
	} else {
		// clear the cached response so we query the stream from now on
		cs.resp = nil
	}
	if status.Code(err) == codes.Canceled || err == io.EOF {
		return nil, gopacket.CaptureInfo{}, io.EOF
	}
	if err != nil {
		return nil, gopacket.CaptureInfo{}, fmt.Errorf("error reading from stream: %w", err)
	}

	data := resp.GetPacket().GetData()
	respCI := resp.GetPacket().GetMetadata().GetCaptureInfo()
	ci := gopacket.CaptureInfo{
		Timestamp:      respCI.GetTimestamp().AsTime(),
		CaptureLength:  int(respCI.GetCaptureLength()),
		Length:         int(respCI.GetLength()),
		InterfaceIndex: int(respCI.GetInterfaceIndex()),
	}
	return data, ci, nil
}

func (cs *captureStreamPacketSource) LinkType() layers.LinkType {
	return cs.linkType
}
