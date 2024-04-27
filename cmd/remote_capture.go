package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
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
	remoteCaptureCmd.Flags().StringP("server", "a", "127.0.0.1:48999", "Remote capper server address to connect to")
	remoteCaptureCmd.Flags().Duration("request-timeout", 0, "Request timeout")
	remoteCaptureCmd.Flags().Duration("connection-timeout", 10*time.Second, "Connection timeout")
	captureFlags := newCaptureFlags()
	remoteCaptureCmd.Flags().AddFlagSet(captureFlags)
}

func runRemoteCapture(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()

	var filter string
	if len(args) == 1 {
		filter = args[0]
	}

	addr, err := cmd.Flags().GetString("server")
	if err != nil {
		return err
	}
	reqTimeout, err := cmd.Flags().GetDuration("request-timeout")
	if err != nil {
		return err
	}
	connTimeout, err := cmd.Flags().GetDuration("connection-timeout")
	if err != nil {
		return err
	}

	captureOpts, err := getCaptureOpts(ctx, filter, cmd.Flags())
	if err != nil {
		return err
	}

	req := &capperpb.CaptureRequest{
		Interface:  captureOpts.Interfaces,
		Filter:     captureOpts.Filter,
		Snaplen:    int64(captureOpts.CaptureConfig.Snaplen),
		NumPackets: captureOpts.CaptureConfig.NumPackets,
		Duration:   durationpb.New(captureOpts.CaptureConfig.CaptureDuration),
		Netns:      captureOpts.CaptureConfig.Netns,
		K8SPodFilter: &capperpb.K8SPodFilter{
			Namespace: captureOpts.K8sNamespace,
			Pod:       captureOpts.K8sPod,
		},
		NoPromiscuousMode: !captureOpts.CaptureConfig.Promisc,
	}
	return remoteCapture(ctx, captureOpts.Logger, addr, connTimeout, reqTimeout, req, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

func remoteCapture(ctx context.Context, log *slog.Logger, addr string, connTimeout, reqTimeout time.Duration, req *capperpb.CaptureRequest, outputFile string, alwaysPrint bool) error {
	clock := clockwork.NewRealClock()
	log.Debug("connecting to server", "server", addr)
	connCtx := ctx
	connCancel := func() {}
	if connTimeout != 0 {
		connCtx, connCancel = context.WithTimeout(ctx, connTimeout)
	}
	conn, err := grpc.DialContext(connCtx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	connCancel()
	if err != nil {
		return fmt.Errorf("error connecting to server: %w", err)
	}
	defer conn.Close()
	c := capperpb.NewCapperClient(conn)

	reqCtx := ctx
	var reqCancel context.CancelFunc
	if reqTimeout != 0 {
		reqCtx, reqCancel = context.WithTimeout(ctx, reqTimeout)
		defer reqCancel()
	}

	start := clock.Now()
	packetsTotal := 0

	log.Debug("creating capture stream")
	stream, err := c.Capture(reqCtx, req)
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	log.Info("capture started", "interface", req.GetInterface(), "snaplen", req.GetSnaplen(), "promisc", !req.GetNoPromiscuousMode(), "num_packets", req.GetNumPackets(), "duration", req.GetDuration())
	defer func() {
		log.Info("capture finished", "interface", req.GetInterface(), "packets", packetsTotal, "capture_duration", clock.Since(start))
	}()

	reader, err := newClientStreamReader(stream)
	if err != nil {
		return err
	}
	defer reader.Close()

	linkType := reader.LinkType()

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

	packetSource := gopacket.NewPacketSource(reader, reader.LinkType())
	packetsCh := packetSource.PacketsCtx(ctx)

	for packet := range packetsCh {
		if err := handler.HandlePacket(packet); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}

	return nil
}

type clientStreamReader struct {
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	stream     capperpb.Capper_CaptureClient

	pcapReader *pcapgo.Reader
	errCh      chan error
}

func newClientStreamReader(stream capperpb.Capper_CaptureClient) (*clientStreamReader, error) {
	r, w := io.Pipe()
	rw := &clientStreamReader{
		pipeReader: r,
		pipeWriter: w,
		stream:     stream,
	}
	// begin reading from the stream and create the pcapReader
	if err := rw.start(); err != nil {
		return nil, err
	}
	return rw, nil
}

func (rw *clientStreamReader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	select {
	case err, ok := <-rw.errCh:
		if !ok {
			err = io.EOF
		}
		return nil, gopacket.CaptureInfo{}, err
	default:
		return rw.pcapReader.ReadPacketData()
	}
}

func (rw *clientStreamReader) LinkType() layers.LinkType {
	return rw.pcapReader.LinkType()
}

func (rw *clientStreamReader) Close() error {
	return rw.pipeReader.Close()
}

func (rw *clientStreamReader) start() error {
	rw.errCh = make(chan error, 1)
	go func() {
		defer close(rw.errCh)
		defer rw.pipeWriter.Close()
		for {
			// Read packets from the gRPC stream and send them to the reader via the pipeWriter
			resp, err := rw.stream.Recv()
			if status.Code(err) == codes.Canceled {
				break
			}
			if err != nil {
				rw.errCh <- fmt.Errorf("error reading from stream: %w", err)
				return
			}
			data := resp.GetData()
			_, err = rw.pipeWriter.Write(data)
			// User closed the reader, return
			if err == io.ErrClosedPipe {
				break
			}
			if err != nil {
				rw.errCh <- fmt.Errorf("error writing data to pipe: %w", err)
				return
			}
		}
		rw.errCh <- nil
	}()

	pcapReader, err := pcapgo.NewReader(rw.pipeReader)
	if err != nil {
		return err
	}
	rw.pcapReader = pcapReader
	return nil
}
