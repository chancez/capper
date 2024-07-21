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
	return queryCapture(ctx, captureOpts.Logger, remoteOpts, req, captureOpts.OutputFile, captureOpts.AlwaysPrint)
}

func queryCapture(ctx context.Context, log *slog.Logger, remoteOpts remoteOpts, req *capperpb.CaptureQueryRequest, outputPath string, alwaysPrint bool) error {
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

	handle, err := newCaptureStreamHandle(log, clock, req.GetCaptureRequest(), stream)
	if err != nil {
		return fmt.Errorf("error creating capture: %w", err)
	}
	defer handle.Close()
	linkType := handle.LinkType()

	handler := newCommonOutputHandler(linkType, uint32(req.GetCaptureRequest().GetSnaplen()), printPackets, outputPath, isDir)
	defer handler.Flush()

	err = handle.Start(ctx, handler)
	if err != nil {
		return fmt.Errorf("error occurred while capturing packets: %w", err)
	}

	return nil
}
