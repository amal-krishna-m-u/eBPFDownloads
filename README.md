```clang -O2 -target bpf -c trace_ext4.c -o trace_ext4.o ```

```go mod init trace_ext4
go get github.com/cilium/ebpf
go run main.go
```