package capture

import (
	"container/heap"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
)

var _ heap.Interface = &PacketHeap{}

// PacketHeap implements heap.Interface
type PacketHeap []TimestampedPacket

func (h PacketHeap) Len() int {
	return len(h)
}

func (h PacketHeap) Less(i, j int) bool {
	return h[i].Timestamp().Before(h[j].Timestamp())
}

func (h PacketHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *PacketHeap) Push(x interface{}) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(TimestampedPacket))
}

func (h *PacketHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// PacketMerger takes multiple PacketSources and combines them
type PacketMerger struct {
	clock  clockwork.Clock
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	// store our packets in a minheap, ordering values by their timestamp.
	// popping elements will return the packet with the lowest timestamp,
	// helping ensure we send packets in-order by timestamp.
	packetHeap *PacketHeap

	heapDrainThreshold int
	flushInterval      time.Duration
	outputBufferSize   int
	exitFlushTimeout   time.Duration

	sources     []NamedPacketSource
	sourcesWg   sync.WaitGroup
	mergeBuffer chan TimestampedPacket
	output      chan TimestampedPacket
}

type NamedPacketSource struct {
	Name string
	PacketSource
}

func NewPacketMerger(log *slog.Logger, sources []NamedPacketSource, heapDrainThreshold int, flushInterval time.Duration, mergeBufferSize int, outputBufferSize int) *PacketMerger {
	ctx, cancel := context.WithCancel(context.Background())
	return &PacketMerger{
		clock:              clockwork.NewRealClock(),
		ctx:                ctx,
		cancel:             cancel,
		log:                log.With("subsystem", "packet-merger"),
		heapDrainThreshold: heapDrainThreshold,
		flushInterval:      flushInterval,
		outputBufferSize:   outputBufferSize,
		exitFlushTimeout:   5 * time.Second,
		sources:            sources,
		packetHeap:         &PacketHeap{},
		// Use a buffered channel so that we can continue to receive packets from sources while merging
		mergeBuffer: make(chan TimestampedPacket, mergeBufferSize),
	}
}

func (pm *PacketMerger) PacketsCtx(ctx context.Context) chan TimestampedPacket {
	if pm.output == nil {
		pm.output = make(chan TimestampedPacket, pm.outputBufferSize)
		go pm.run(ctx)
	}
	return pm.output
}

func (pm *PacketMerger) sendPacket(ctx context.Context) {
	// helper to send a packet if one exists, blocking until once does exist or
	// the context is cancelled
	p := heap.Pop(pm.packetHeap).(TimestampedPacket)
	select {
	case pm.output <- p:
	case <-ctx.Done():
	}
}

func (pm *PacketMerger) drainHeap(ctx context.Context, timeout time.Duration) int {
	// flush the entire heap, with a timeout for flushing
	sent := 0
	newCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	for pm.packetHeap.Len() > 0 {
		pm.sendPacket(newCtx)
		sent++
	}
	return sent
}

func (pm *PacketMerger) run(ctx context.Context) {
	pm.log.Debug("merger started")

	defer func() {
		pm.log.Debug("merger finished")
		close(pm.output)
	}()

	// start a consumer goroutine that buffers and merges the packets from each
	// source before sending them to the output
	var consumerWg sync.WaitGroup
	consumerWg.Add(1)
	go func() {
		pm.log.Debug("merger consumer started")
		defer func() {
			pm.log.Debug("merger consumer finished")
			consumerWg.Done()
		}()

		ticker := pm.clock.NewTicker(pm.flushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// drain the entire heap
				sent := pm.drainHeap(ctx, pm.exitFlushTimeout)
				pm.log.Debug("merger consumer cancelled: flushed packets", "num_packets", sent, "flushInterval", pm.flushInterval, "heapSize", pm.packetHeap.Len())
				return
			case p, ok := <-pm.mergeBuffer:
				if !ok {
					// drain the entire heap
					sent := pm.drainHeap(ctx, pm.exitFlushTimeout)
					pm.log.Debug("merger consumer source closed: flushed packets", "num_packets", sent, "flushInterval", pm.flushInterval, "heapSize", pm.packetHeap.Len())
					return
				}

				heap.Push(pm.packetHeap, p)
				sent := 0
				// Buffer some packets in case we need to re-order, so only packets
				// send after we've gotten to the heapDrainThreshold, and always keep some
				// buffered.
				// If there's a long delay, the ticker will flush some of the pending
				// packets.
				for pm.packetHeap.Len() > 0 && pm.packetHeap.Len() >= pm.heapDrainThreshold {
					pm.sendPacket(ctx)
					sent++
				}
				if sent > 0 {
					// Reset the ticker if we recently sent new packets
					ticker.Reset(pm.flushInterval)
				}
			case <-ticker.Chan():
				// Send 1/2 the heap if we haven't sent anything in a while
				sent := 0
				for ; pm.packetHeap.Len() > 0 && sent < pm.packetHeap.Len()/2 || pm.packetHeap.Len() == 1; sent++ {
					pm.sendPacket(ctx)
				}
				pm.log.Debug("reached flushInterval: flushed packets", "num_packets", sent, "flushInterval", pm.flushInterval, "heapSize", pm.packetHeap.Len())
			}
		}
	}()

	pm.log.Debug("starting merger producers")
	for _, src := range pm.sources {
		src := src
		pm.AddSource(src)
	}

	pm.log.Debug("waiting for consumer to stop")
	// wait for the consumer to complete
	consumerWg.Wait()
	// consumers are done, stop the sources and stop the merger merger
	pm.stop()
}

func (pm *PacketMerger) stop() {
	pm.log.Debug("stopping merger")
	pm.cancel()
	pm.log.Debug("waiting for sources to stop")
	// Wait for the sources
	pm.sourcesWg.Wait()
	// After the the input sources are finished, tell the consumer to return by
	// closing mergeBuffer
	close(pm.mergeBuffer)
	pm.log.Debug("merger stopped")
}

func (pm *PacketMerger) AddSource(src NamedPacketSource) {
	// start a producer goroutine for each source
	pm.sourcesWg.Add(1)
	go func() {
		pm.log.Debug("merger producer started", "source", src.Name)
		defer func() {
			pm.log.Debug("merger producer finished", "source", src.Name)
			pm.sourcesWg.Done()
		}()

		// send all the packets coming from this source to the merger/consumer goroutine
		for packet := range src.PacketsCtx(pm.ctx) {
			select {
			case <-pm.ctx.Done():
				return
			case pm.mergeBuffer <- packet:
			}
		}
	}()
}
