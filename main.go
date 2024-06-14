package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native bpf trace_ext4.c -- -I../bpf/headers

type ext4Event struct {
	PID     uint32
	Pblk    uint64
	LblkLen uint32
	Comm    [16]byte
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tpEnterLink, err := link.Tracepoint("ext4", "ext4_ext_map_blocks_exit", objs.TraceExt4ExtMapBlocksExit, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %s", err)
	}
	defer tpEnterLink.Close()

	events := objs.Events
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		log.Fatalf("Failed to create ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				log.Fatalf("Failed to read record: %s", err)
			}
			var event ext4Event
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				log.Fatalf("Failed to decode event: %s", err)
			}
			log.Printf("PID: %d, Pblk: %d, LblkLen: %d, Comm: %s\n", event.PID, event.Pblk, event.LblkLen, event.Comm)
		}
	}()

	<-stopper
}
