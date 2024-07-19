package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sync/errgroup"
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

	if len(captureOpts.K8sPod) != 0 {
		if captureOpts.K8sNamespace == "" {
			captureOpts.K8sNamespace = "default"
		}
	}
	req := &capperpb.CaptureRequest{
		Interface:  captureOpts.Interfaces,
		Filter:     captureOpts.Filter,
		Snaplen:    int64(captureOpts.CaptureConfig.Snaplen),
		NumPackets: captureOpts.CaptureConfig.NumPackets,
		Duration:   durationpb.New(captureOpts.CaptureConfig.CaptureDuration),
		K8SPodFilter: &capperpb.Pod{
			Namespace: captureOpts.K8sNamespace,
			Name:      podName,
		},
		NoPromiscuousMode: !captureOpts.CaptureConfig.Promisc,
		BufferSize:        int64(captureOpts.CaptureConfig.BufferSize),
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

	pipeReader, pipeWriter := io.Pipe()
	// These will be closed when the goroutine returns, resulting in the
	// PacketsCtx below returning.
	defer pipeReader.Close()

	reader, err := newLazyPcapReader(pipeReader)
	if err != nil {
		return err
	}

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		defer pipeWriter.Close()
		for {
			resp, err := stream.Recv()
			if status.Code(err) == codes.Canceled {
				return nil
			}
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("error reading from stream: %w", err)
			}

			data := resp.GetData()

			_, err = pipeWriter.Write(data)
			if err != nil {
				return err
			}
		}
	})

	eg.Go(func() error {
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

		packetSource := gopacket.NewPacketSource(reader, linkType)
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
	})

	err = eg.Wait()
	if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return nil
}

// LazyPcapReader is a pcapgo.Reader but it does not read from the provided
// io.Reader until ReadPacketData is called.
type LazyPcapReader struct {
	reader io.Reader

	once *sync.Once
	err  error

	pcapReader *pcapgo.Reader
}

func newLazyPcapReader(r io.Reader) (*LazyPcapReader, error) {
	rw := &LazyPcapReader{
		reader: r,
		once:   &sync.Once{},
	}
	return rw, nil
}

func (r *LazyPcapReader) init() {
	if r.pcapReader == nil {
		// NewReader is initialized on the first call of one of it's method instead
		// of at initialization because it begin to read from the underlying io.Reader
		// and blocks until there's something to read.
		pcapReader, err := pcapgo.NewReader(r.reader)
		if err != nil {
			r.err = err
		}
		r.pcapReader = pcapReader
	}
}

func (r *LazyPcapReader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	r.once.Do(r.init)
	if r.err != nil {
		return nil, gopacket.CaptureInfo{}, err
	}
	return r.pcapReader.ReadPacketData()
}

// // LinkType returns network, as a layers.LinkType.
func (r *LazyPcapReader) LinkType() layers.LinkType {
	r.once.Do(r.init)
	return r.pcapReader.LinkType()
}

// Snaplen returns the snapshot length of the capture file.
func (r *LazyPcapReader) Snaplen() uint32 {
	r.once.Do(r.init)
	return r.pcapReader.Snaplen()
}
