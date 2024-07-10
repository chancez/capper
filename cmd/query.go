package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
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

var queryCmd = &cobra.Command{
	Use:   "query [filter]",
	Short: "Capture packets remotely ",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runQuery,
}

func init() {
	rootCmd.AddCommand(queryCmd)

	for _, fs := range []*pflag.FlagSet{
		newCaptureFlags(),
		newRemoteFlags(),
		newQueryFlags(),
	} {
		queryCmd.Flags().AddFlagSet(fs)
	}
}

func newQueryFlags() *pflag.FlagSet {
	queryFlags := pflag.NewFlagSet("query-flags", pflag.ExitOnError)
	queryFlags.StringSlice("node", nil, "Run the capture on the specified node(s).")
	return queryFlags
}

func getQueryOpts(fs *pflag.FlagSet) (queryFlags, error) {
	nodes, err := fs.GetStringSlice("node")
	if err != nil {
		return queryFlags{}, err
	}

	return queryFlags{
		Nodes: nodes,
	}, nil
}

type queryFlags struct {
	Nodes []string
}

func runQuery(cmd *cobra.Command, args []string) error {
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
	queryOpts, err := getQueryOpts(cmd.Flags())
	if err != nil {
		return err
	}

	var targets []*capperpb.CaptureQueryTarget
	for _, node := range queryOpts.Nodes {
		targets = append(targets, &capperpb.CaptureQueryTarget{
			Target: &capperpb.CaptureQueryTarget_Node{
				Node: node,
			},
		})
	}
	for _, pod := range captureOpts.K8sPod {
		targets = append(targets, &capperpb.CaptureQueryTarget{
			Target: &capperpb.CaptureQueryTarget_Pod{
				Pod: &capperpb.Pod{
					Namespace: captureOpts.K8sNamespace,
					Name:      pod,
				},
			},
		})
	}

	req := &capperpb.CaptureQueryRequest{
		Targets: targets,
		CaptureRequest: &capperpb.CaptureRequest{
			Interface:         captureOpts.Interfaces,
			Filter:            captureOpts.Filter,
			Snaplen:           int64(captureOpts.CaptureConfig.Snaplen),
			NumPackets:        captureOpts.CaptureConfig.NumPackets,
			Duration:          durationpb.New(captureOpts.CaptureConfig.CaptureDuration),
			NoPromiscuousMode: !captureOpts.CaptureConfig.Promisc,
			BufferSize:        int64(captureOpts.CaptureConfig.BufferSize),
		},
	}
	return query(ctx, captureOpts.Logger, remoteOpts, req, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

func query(ctx context.Context, log *slog.Logger, remoteOpts remoteOpts, req *capperpb.CaptureQueryRequest, outputFile string, alwaysPrint bool) error {
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
	c := capperpb.NewQuerierClient(conn)

	reqCtx := ctx
	var reqCancel context.CancelFunc
	if remoteOpts.RequestTimeout != 0 {
		reqCtx, reqCancel = context.WithTimeout(ctx, remoteOpts.RequestTimeout)
		defer reqCancel()
	}

	start := clock.Now()
	packetsTotal := 0

	log.Debug("creating capture stream")
	stream, err := c.CaptureQuery(reqCtx, req)
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	log.Info("capture started", "interface", req.GetCaptureRequest().GetInterface(), "snaplen", req.GetCaptureRequest().GetSnaplen(), "promisc", !req.GetCaptureRequest().GetNoPromiscuousMode(), "num_packets", req.GetCaptureRequest().GetNumPackets(), "duration", req.GetCaptureRequest().GetDuration())
	defer func() {
		log.Info("capture finished", "interface", req.GetCaptureRequest().GetInterface(), "packets", packetsTotal, "capture_duration", clock.Since(start))
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

		// This goroutine prints and writes packets after retrieving them from the merger
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

				writeHandler, err := capture.NewPcapWriterHandler(writer, linkType, uint32(req.GetCaptureRequest().GetSnaplen()))
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

	// This goroutine reads from the gRPC stream
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
