#!/bin/bash
# Build translator first
cd ~/veritas/shallow-embedding && make clean && make

# Build syz-manager
cd ~/veritas/syzkaller
export PATH=$HOME/veritas/go-env/go/bin:$PATH
REV="c1551704ab4760d0d65fb8e0d023606c8d69425b"
DATE=$(date +%Y%m%d-%H%M%S)
CGO_CXXFLAGS="-std=c++17 -I$HOME/veritas/shallow-embedding/src" \
CGO_LDFLAGS="-L$HOME/veritas/shallow-embedding -lshallow-embedding -lstdc++ -lelf -lz -lzstd" \
go build "-ldflags=-s -w -X github.com/google/syzkaller/prog.GitRevision=$REV -X github.com/google/syzkaller/prog.gitRevisionDate=$DATE" \
  -o ./bin/syz-manager github.com/google/syzkaller/syz-manager
echo "Done: $(ls -la bin/syz-manager)"
