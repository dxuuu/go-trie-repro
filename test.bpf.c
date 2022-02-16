// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"

struct v4_lpm_key {
	u32 prefix_len;
	u128 uuid;
	u32 addr;
} __attribute__((packed));

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 128);
	__type(key, struct v4_lpm_key);
	__type(value, u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} map SEC(".maps");
