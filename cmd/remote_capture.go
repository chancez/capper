package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/jonboulle/clockwork"
	"github.com/spf13/cobra"
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
	remoteCaptureCmd.Flags().StringP("server", "a", "127.0.0.1:48999", "Remote capper server address to connect to")
	remoteCaptureCmd.Flags().Duration("request-timeout", 0, "Request timeout")
	remoteCaptureCmd.Flags().Duration("connection-timeout", 10*time.Second, "Connection timeout")
	remoteCaptureCmd.Flags().String("node-name", "", "Run the capture on a specific node")
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
	nodeName, err := cmd.Flags().GetString("node-name")
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
		K8SPodFilter: &capperpb.K8SPodFilter{
			Namespace: captureOpts.K8sNamespace,
			Pod:       captureOpts.K8sPod,
		},
		NoPromiscuousMode: !captureOpts.CaptureConfig.Promisc,
		NodeName:          nodeName,
	}
	return remoteCapture(ctx, captureOpts.Logger, addr, connTimeout, reqTimeout, req, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

func remoteCapture(ctx context.Context, log *slog.Logger, addr string, connTimeout, reqTimeout time.Duration, req *capperpb.CaptureRequest, outputFile string, alwaysPrint bool) error {
	var outputDir string
	if outputFile != "" {
		fi, err := os.Stat(outputFile)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil && fi.IsDir() {
			outputDir = outputFile
		}
	}

	printPackets := outputFile == "" || alwaysPrint
	// merging packets is required to print them or send them to a non-directory file output
	singleFileOutput := (outputFile != "" && outputDir == "")
	mergePackets := printPackets || singleFileOutput

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

	linkTypeCh := make(chan layers.LinkType)

	var eg *errgroup.Group
	eg, ctx = errgroup.WithContext(ctx)
	var merger *capture.PacketMerger
	if mergePackets {
		log.Debug("starting packet merger")
		heapDrainThreshold := 10
		flushInterval := time.Second
		mergeBufferSize := 100
		merger = capture.NewPacketMerger(log, nil, heapDrainThreshold, flushInterval, mergeBufferSize, 0)

		eg.Go(func() error {
			var handlers []capture.PacketHandler
			if printPackets {
				handlers = append(handlers, capture.PacketPrinterHandler)
			}

			if singleFileOutput {
				var writer io.Writer
				if outputFile == "-" {
					writer = os.Stdout
				} else {
					f, err := os.Create(outputFile)
					if err != nil {
						return fmt.Errorf("error opening output: %w", err)
					}
					writer = f
					defer f.Close()
				}

				// We need the linkType to create the writer.
				// This will be set based on the first packet's linkType when we
				// receive it from the stream
				var linkType layers.LinkType
				if linkType == layers.LinkTypeNull {
					select {
					case linkType = <-linkTypeCh:
					case <-ctx.Done():
						return ctx.Err()
					}
				}

				writeHandler, err := capture.NewPcapWriterHandler(writer, linkType, uint32(req.GetSnaplen()))
				if err != nil {
					return err
				}
				handlers = append(handlers, writeHandler)
			}
			handler := capture.ChainPacketHandlers(handlers...)
			for packet := range merger.PacketsCtx(ctx) {
				if err := handler.HandlePacket(packet); err != nil {
					return err
				}
			}
			return nil
		})
	}

	eg.Go(func() error {
		configuredLinkType := false
		writers := make(map[string]io.Writer)
		for {
			// Read packets from the gRPC stream and send them to the reader via the pipeWriter
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

			// Every gRPC message contains a single packet
			packetsTotal++

			identifier := resp.GetIdentifier()
			data := resp.GetData()
			linkType := layers.LinkType(resp.GetLinkType())

			// When writing to a file, we need to know the linkType so we can write the header,
			// so send it to the merger.
			if singleFileOutput && !configuredLinkType {
				linkTypeCh <- linkType
				configuredLinkType = true
				close(linkTypeCh)
			}

			// Get the writer for the given packet source
			writer, exists := writers[identifier]
			if !exists {
				// If we're merging packets, we need to parse them and send them to the merger.
				if mergePackets {
					// Create a pipe that our pcapReader can read from, and set the
					// writer for this identity to the pipeWriter which in turn, will
					// write to the pcapReader that the merger is reading from.
					pipeReader, pipeWriter := io.Pipe()
					// These will be closed when the goroutine returns, resulting in the
					// PacketsCtx below returning.
					defer pipeWriter.Close()
					defer pipeReader.Close()
					writer = pipeWriter

					pcapReader, err := newLazyPcapReader(pipeReader)
					if err != nil {
						return err
					}

					src := gopacket.NewPacketSource(pcapReader, linkType)
					merger.AddSource(capture.NamedPacketSource{
						Name:         identifier,
						PacketSource: src,
					})

				} else if outputDir != "" {
					// If we're writing to a directory, then store each output stream into
					// it's own file in the specified directory.
					// If we're writing to a single file, that's handled in the merger goroutine instead.

					// The packet identifier is the file name, it contains the peer
					// hostname, netns, and interface and the .pcap extension.
					f, err := os.Create(filepath.Join(outputDir, identifier))
					if err != nil {
						return fmt.Errorf("error opening output: %w", err)
					}
					defer f.Close()
					writer = f
				}

				writers[identifier] = writer
			}

			// Write to our final destination.
			_, err = writer.Write(data)
			if err != nil {
				return err
			}
		}
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
