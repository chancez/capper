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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	if len(captureOpts.K8sPod) != 0 {
		ns := captureOpts.K8sNamespace
		if ns == "" {
			ns = "default"
		}
		for _, pod := range captureOpts.K8sPod {
			targets = append(targets, &capperpb.CaptureQueryTarget{
				Target: &capperpb.CaptureQueryTarget_Pod{
					Pod: &capperpb.Pod{
						Namespace: ns,
						Name:      pod,
					},
				},
			})
		}
	} else if len(captureOpts.K8sPod) == 0 && captureOpts.K8sNamespace != "" {
		// Query all pods in the specified namespace if namespace is set, but no pods
		// specified
		targets = append(targets, &capperpb.CaptureQueryTarget{
			Target: &capperpb.CaptureQueryTarget_PodNamespace{
				PodNamespace: captureOpts.K8sNamespace,
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

func query(ctx context.Context, log *slog.Logger, remoteOpts remoteOpts, req *capperpb.CaptureQueryRequest, outputPath string, alwaysPrint bool) error {
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
	// merging packets is required to print them or send them to a non-directory file output
	singleFileOutput := (outputPath != "" && !isDir)
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

	log.Debug("creating capture stream")
	stream, err := c.CaptureQuery(reqCtx, req)
	if err != nil {
		return fmt.Errorf("error creating stream: %w", err)
	}

	handle, err := newCaptureQueryHandle(log, clock, req.GetCaptureRequest(), stream, mergePackets)
	if err != nil {
		return fmt.Errorf("error creating capture: %w", err)
	}
	defer handle.Close()
	linkType := handle.LinkType()

	handler := newCommonHandler(linkType, uint32(req.GetCaptureRequest().GetSnaplen()), printPackets, outputPath, isDir)
	defer handler.Flush()

	err = handle.Start(ctx, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}

	return nil
}

type commonHandler struct {
	handler capture.PacketHandler
}

func newCommonHandler(linkType layers.LinkType, snaplen uint32, printPackets bool, outputPath string, isDir bool) *commonHandler {
	var handlers []capture.PacketHandler
	if printPackets {
		handlers = append(handlers, capture.PacketPrinterHandler)
	}
	if outputPath != "" {
		outputFileHandler := newOutputFileHandler(outputPath, isDir, linkType, snaplen)
		handlers = append(handlers, outputFileHandler)
	}
	handler := capture.ChainPacketHandlers(handlers...)
	return &commonHandler{
		handler: handler,
	}
}

func (ch *commonHandler) HandlePacket(p gopacket.Packet) error {
	return ch.handler.HandlePacket(p)
}

func (ch *commonHandler) Flush() error {
	return ch.handler.Flush()
}

type captureQuery struct {
	log          *slog.Logger
	clock        clockwork.Clock
	captureReq   *capperpb.CaptureRequest
	source       *captureStreamPacketSource
	linkType     layers.LinkType
	mergePackets bool
}

func newCaptureQueryHandle(log *slog.Logger, clock clockwork.Clock, req *capperpb.CaptureRequest, stream captureStream, mergePackets bool) (*captureQuery, error) {
	streamSource, err := newCaptureStreamPacketSource(stream)
	if err != nil {
		return nil, fmt.Errorf("error creating capture stream packet source: %w", err)
	}

	linkType := streamSource.LinkType()
	return &captureQuery{
		log:          log,
		clock:        clock,
		captureReq:   req,
		source:       streamSource,
		linkType:     linkType,
		mergePackets: mergePackets,
	}, nil
}

func (cq *captureQuery) Start(ctx context.Context, handler capture.PacketHandler) error {
	start := cq.clock.Now()
	packetsTotal := 0
	cq.log.Info("capture started", "interface", cq.captureReq.GetInterface(), "snaplen", cq.captureReq.GetSnaplen(), "promisc", !cq.captureReq.GetNoPromiscuousMode(), "num_packets", cq.captureReq.GetNumPackets(), "duration", cq.captureReq.GetDuration())

	defer cq.log.Info("capture finished", "interface", cq.captureReq.GetInterface(), "packets", packetsTotal, "capture_duration", cq.clock.Since(start))

	var packetSource capture.PacketSource = gopacket.NewPacketSource(cq.source, cq.linkType)
	if cq.mergePackets {
		cq.log.Debug("starting packet merger")
		heapDrainThreshold := 10
		flushInterval := time.Second
		mergeBufferSize := 100
		packetSource = capture.NewPacketMerger(
			cq.log,
			[]capture.NamedPacketSource{{Name: "grpc-stream", PacketSource: packetSource}},
			heapDrainThreshold, flushInterval, mergeBufferSize, 0,
		)
	}

	defer handler.Flush()
	for packet := range packetSource.PacketsCtx(ctx) {
		if err := handler.HandlePacket(packet); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		packetsTotal++
	}

	return nil
}

func (cq *captureQuery) LinkType() layers.LinkType {
	return cq.linkType
}

func (cq *captureQuery) Close() {
}

type outputFileHandler struct {
	outputPath string
	isDir      bool
	writers    map[string]capture.PacketWriter
	closers    []io.Closer
	linkType   layers.LinkType
	snaplen    uint32
}

func newOutputFileHandler(outputPath string, isDir bool, linkType layers.LinkType, snaplen uint32) *outputFileHandler {
	return &outputFileHandler{
		outputPath: outputPath,
		isDir:      isDir,
		writers:    make(map[string]capture.PacketWriter),
		linkType:   linkType,
		snaplen:    snaplen,
	}
}

func (h *outputFileHandler) HandlePacket(p gopacket.Packet) error {
	ancillaryData, err := getCapperAncillaryData(p)
	if err != nil {
		return err
	}
	identifier := ancillaryData.GetIdentifier()
	if identifier == "" {
		return fmt.Errorf("no capper identifier in AncillaryPacketData")
	}
	packetWriter, exists := h.writers[identifier]
	if !exists {
		var w io.Writer
		if h.isDir {
			f, err := os.Create(filepath.Join(h.outputPath, identifier))
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			h.closers = append(h.closers, f)
			w = f
		} else if h.outputPath == "-" {
			w = os.Stdout
		} else {
			f, err := os.Create(h.outputPath)
			if err != nil {
				return fmt.Errorf("error opening output: %w", err)
			}
			h.closers = append(h.closers, f)
			w = f
		}
		packetWriter = capture.NewPcapWriter(w, h.linkType, h.snaplen)
	}
	return packetWriter.WritePacket(p.Metadata().CaptureInfo, p.Data())
}

func (h *outputFileHandler) Flush() error {
	var err error
	for _, w := range h.writers {
		err = errors.Join(err, w.Flush())
	}
	for _, closer := range h.closers {
		err = errors.Join(err, closer.Close())
	}
	return err
}

func getCapperAncillaryData(p gopacket.Packet) (*capperpb.AncillaryPacketData, error) {
	pancillaryData := p.Metadata().AncillaryData
	if len(pancillaryData) == 0 {
		return nil, fmt.Errorf("no gopacket AncillaryData")
	}
	var ancillaryData *capperpb.AncillaryPacketData
	for _, ad := range pancillaryData {
		var ok bool
		ancillaryData, ok = ad.(*capperpb.AncillaryPacketData)
		if ok {
			break
		}
	}
	if ancillaryData == nil {
		return nil, fmt.Errorf("no capper AncillaryPacketData found in gopacket AncillaryData")
	}
	return ancillaryData, nil
}
