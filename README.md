## Bug in the golang library?

```sh
$ sudo ./go-trie-repro
error: failed to lookup 1.2.3.4/32: lookup: key does not exist
```

Here's the same program written in C (reused the selftest file) that runs OK:
```diff
diff --git a/tools/testing/selftests/bpf/test_lpm_map.c b/tools/testing/selftests/bpf/test_lpm_map.c
index baa3e3ecae82..f62b90e94b41 100644
--- a/tools/testing/selftests/bpf/test_lpm_map.c
+++ b/tools/testing/selftests/bpf/test_lpm_map.c
@@ -423,6 +423,46 @@ static void test_lpm_ipaddr(void)
 	close(map_fd_ipv6);
 }
 
+static void test_lpm_ipaddr_uuid(void)
+{
+	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
+	struct bpf_lpm_trie_key *key_ipv4;
+	size_t key_size_ipv4;
+	int map_fd_ipv4;
+	__u8 value;
+
+	key_size_ipv4 = sizeof(*key_ipv4) + 16 + sizeof(__u32);
+	key_ipv4 = alloca(key_size_ipv4);
+
+	map_fd_ipv4 = bpf_map_create(BPF_MAP_TYPE_LPM_TRIE, NULL,
+				     key_size_ipv4, sizeof(value),
+				     100, &opts);
+	assert(map_fd_ipv4 >= 0);
+
+	value = 3;
+	key_ipv4->prefixlen = 128 + 24;
+	memset(key_ipv4->data, 0xFF, 16);
+	inet_pton(AF_INET, "1.2.3.0", key_ipv4->data + 16);
+	assert(bpf_map_update_elem(map_fd_ipv4, key_ipv4, &value, 0) == 0);
+
+	/* Set tprefixlen to maximum for lookups */
+	key_ipv4->prefixlen = 128 + 32;
+
+	/* Test some lookups that should come back with a value */
+	memset(key_ipv4->data, 0xFF, 16);
+	inet_pton(AF_INET, "1.2.3.4", key_ipv4->data + 16);
+	assert(bpf_map_lookup_elem(map_fd_ipv4, key_ipv4, &value) == 0);
+	assert(value == 3);
+
+	/* Test lookup that should fail */
+	memset(key_ipv4->data, 0xFF, 16);
+	inet_pton(AF_INET, "5.5.5.5", key_ipv4->data + 16);
+	assert(bpf_map_lookup_elem(map_fd_ipv4, key_ipv4, &value) == -1 &&
+	       errno == ENOENT);
+
+	close(map_fd_ipv4);
+}
+
 static void test_lpm_delete(void)
 {
 	LIBBPF_OPTS(bpf_map_create_opts, opts, .map_flags = BPF_F_NO_PREALLOC);
@@ -787,6 +827,9 @@ int main(void)
 {
 	int i;
 
+	test_lpm_ipaddr_uuid();
+	return 0;
+
 	/* we want predictable, pseudo random tests */
 	srand(0xf00ba1);
```
