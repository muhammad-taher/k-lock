TARGET_BPF := dist/rce_core.o
TARGET_LOADER := dist/rce_guard
BPF_SRC := bpf/rce_core.c
LOADER_SRC := src/main.cpp src/utils.cpp src/monitor.cpp

all: $(TARGET_BPF) $(TARGET_LOADER) config

$(TARGET_BPF): $(BPF_SRC)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I bpf -c $(BPF_SRC) -o $(TARGET_BPF)

$(TARGET_LOADER): $(LOADER_SRC)
	clang++ -g -O2 -I src/include $(LOADER_SRC) -o $(TARGET_LOADER) -lbpf -lelf -lz

config:
	cp config.json dist/config.json 2>/dev/null || echo "Info: No root config.json found to copy."

clean:
	rm -f dist/rce_core.o dist/rce_guard
