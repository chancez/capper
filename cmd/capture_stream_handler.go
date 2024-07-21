package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/chancez/capper/pkg/capture"
	capperpb "github.com/chancez/capper/proto/capper"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/jonboulle/clockwork"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type captureStreamHandle struct {
	log        *slog.Logger
	clock      clockwork.Clock
	captureReq *capperpb.CaptureRequest
	source     *captureStreamPacketSource
	linkType   layers.LinkType
}

func newCaptureStreamHandle(log *slog.Logger, clock clockwork.Clock, req *capperpb.CaptureRequest, stream captureStream) (*captureStreamHandle, error) {
	streamSource, err := newCaptureStreamPacketSource(stream)
	if err != nil {
		return nil, fmt.Errorf("error creating capture stream packet source: %w", err)
	}

	linkType := streamSource.LinkType()
	return &captureStreamHandle{
		log:        log,
		clock:      clock,
		captureReq: req,
		source:     streamSource,
		linkType:   linkType,
	}, nil
}

func (csh *captureStreamHandle) Start(ctx context.Context, handler capture.PacketHandler) error {
	start := csh.clock.Now()
	packetsTotal := 0
	csh.log.Info("capture started", "interface", csh.captureReq.GetInterface(), "snaplen", csh.captureReq.GetSnaplen(), "promisc", !csh.captureReq.GetNoPromiscuousMode(), "num_packets", csh.captureReq.GetNumPackets(), "duration", csh.captureReq.GetDuration())

	defer func() {
		csh.log.Info("capture finished", "interface", csh.captureReq.GetInterface(), "packets", packetsTotal, "capture_duration", csh.clock.Since(start))
	}()

	packetSource := gopacket.NewPacketSource(csh.source, csh.linkType)

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

func (csh *captureStreamHandle) LinkType() layers.LinkType {
	return csh.linkType
}

func (csh *captureStreamHandle) Close() {
}

type captureStream interface {
	Recv() (*capperpb.CaptureResponse, error)
}

type packetGetter interface {
	GetPacket() *capperpb.Packet
}

type captureStreamPacketSource struct {
	stream captureStream

	resp     packetGetter
	linkType layers.LinkType
}

func newCaptureStreamPacketSource(stream captureStream) (*captureStreamPacketSource, error) {
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
	if respCI.GetAncillaryData() != nil {
		ci.AncillaryData = append(ci.AncillaryData, respCI.GetAncillaryData())
	}
	return data, ci, nil
}

func (cs *captureStreamPacketSource) LinkType() layers.LinkType {
	return cs.linkType
}
