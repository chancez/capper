package minheap

import (
	"container/heap"

	"github.com/gopacket/gopacket"
)

var _ heap.Interface = &PacketHeap{}

// PacketHeap implements heap.Interface
type PacketHeap []gopacket.Packet

func (h PacketHeap) Len() int {
	return len(h)
}

func (h PacketHeap) Less(i, j int) bool {
	return h[i].Metadata().Timestamp.Before(h[j].Metadata().Timestamp)
}

func (h PacketHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h *PacketHeap) Push(x interface{}) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(gopacket.Packet))
}

func (h *PacketHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
