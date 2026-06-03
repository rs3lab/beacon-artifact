#!/bin/bash
# Build translator first
cd ~/veritas/shallow-embedding && make clean && make

# Build syz-manager
cd ~/veritas/syzkaller
export PATH=$HOME/veritas/go-env/go/bin:$PATH
REV="67e403dc3123dc999073b0bdf70c8bcde4651679+"
DATE=$(date +%Y%m%d-%H%M%S)
CGO_CXXFLAGS="-std=c++17 -I$HOME/veritas/shallow-embedding/src" \
CGO_LDFLAGS="-L$HOME/veritas/shallow-embedding -lshallow-embedding -lstdc++ -lelf -lz -lzstd" \
go build "-ldflags=-s -w -X github.com/google/syzkaller/prog.GitRevision=$REV -X github.com/google/syzkaller/prog.gitRevisionDate=$DATE" \
  -o ./bin/syz-manager github.com/google/syzkaller/syz-manager
echo "Done: $(ls -la bin/syz-manager)"
