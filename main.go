package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc /bin/clang bpf test.bpf.c

type c_u128 [16]uint8
type c_v4LpmKey struct {
	prefixLen uint32
	uuid      c_u128
	addr      uint32
}

func run() error {
	bpfObjs := bpfObjects{}
	err := loadBpfObjects(&bpfObjs, nil)
	if err != nil {
		return fmt.Errorf("failed to load BPF objects: %v", err)
	}
	defer bpfObjs.Close()
	m := bpfObjs.bpfMaps.Map

	// insert 1.2.3.0/24
	key := c_v4LpmKey{
		prefixLen: uint32(128 + 24),
		uuid:      [16]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		addr:      0x01020300,
	}
	val := uint8(1)
	err = m.Update(key, val, ebpf.UpdateAny)
	if err != nil {
		return fmt.Errorf("failed to update map: %v", err)
	}

	// lookup 1.2.3.4/32
	val = 0
	key = c_v4LpmKey{
		prefixLen: uint32(128 + 32),
		uuid:      [16]uint8{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
		addr:      0x01020304,
	}
	err = m.Lookup(key, &val)
	if err != nil {
		return fmt.Errorf("failed to lookup 1.2.3.4/32: %v", err)
	}
	if val != 1 {
		return fmt.Errorf("wrong val: %v", val)
	}

	return nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
