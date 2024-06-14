package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type ext4Event struct {
	PID     uint32
	Pblk    uint64
	LblkLen uint32
	Comm    [16]byte
}

func main() {
	// Load the compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("trace_ext4.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create eBPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["trace_ext4_ext_map_blocks_exit"]
	if prog == nil {
		log.Fatalf("Failed to find eBPF program: %v", err)
	}

	// Attach the eBPF program to the tracepoint
	tp, err := link.Tracepoint("ext4", "ext4_ext_map_blocks_exit", prog)
	if err != nil {
		log.Fatalf("Failed to attach to tracepoint: %v", err)
	}
	defer tp.Close()

	// Open the perf event reader
	reader, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to open perf reader: %v", err)
	}
	defer reader.Close()

	// Set up signal handling to exit cleanly
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Waiting for events...")

	for {
		select {
		case <-sig:
			log.Println("Exiting...")
			return
		default:
			record, err := reader.Read()
			if err != nil {
				if perf.IsEndOfBuffer(err) {
					continue
				}
				log.Fatalf("Failed to read from perf reader: %v", err)
			}

			var event ext4Event
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Fatalf("Failed to decode received data: %v", err)
			}

			fmt.Printf("PID: %d, Pblk: %d, LblkLen: %d, Comm: %s\n", event.PID, event.Pblk, event.LblkLen, string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)]))
		}
	}
}
