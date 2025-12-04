# Makefile for the ATSC 3.0 LLS Parser

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -g -Ilibhdhomerun $(shell pkg-config --cflags libxml-2.0)
LDFLAGS = $(shell pkg-config --libs libxml-2.0) -lpcap -lz -lssl -lcrypto -lhdhomerun

# Source and Executable files
SRCS = a3render.c input.c plp.c l1_detail_parser.c crypto.c esg.c bps.c utility.c
TARGET = render

# Default target: build the executable
all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Target to clean up the build directory
clean:
	rm -f $(TARGET) 

# Phony targets
.PHONY: all clean
