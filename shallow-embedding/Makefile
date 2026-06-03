CXX    = g++
CFLAGS = -std=c++17 -Wall -Wextra -O2 -Isrc

LIB_SRCS = src/helpers.cpp    \
           src/arith.cpp      \
           src/datamov.cpp    \
           src/memory.cpp     \
           src/ctrlflow.cpp   \
           src/translator.cpp

LIB_OBJS = $(LIB_SRCS:.cpp=.o)

all: shallow-embedding libshallow-embedding.a

shallow-embedding: $(LIB_OBJS) src/main.o
	$(CXX) $(CFLAGS) -o $@ $^

libshallow-embedding.a: $(LIB_OBJS)
	ar rcs $@ $^

src/%.o: src/%.cpp src/translator.hpp
	$(CXX) $(CFLAGS) -c $< -o $@

clean:
	rm -f shallow-embedding libshallow-embedding.a src/*.o

.PHONY: all clean