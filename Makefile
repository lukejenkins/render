# Makefile for the ATSC 3.0 LLS Parser with AC-4 Parser

# Detect OS
UNAME_S := $(shell uname -s)

# Compiler and Flags
CC = gcc
CFLAGS = -Wall -g -Ilibhdhomerun $(shell pkg-config --cflags libxml-2.0 libavcodec libavutil)

# Base libraries (common to all platforms)
LIBS = $(shell pkg-config --libs libxml-2.0 libavcodec libavutil) -lpcap -lz -lssl -lcrypto

# Platform-specific configuration
ifeq ($(UNAME_S),Darwin)
    # macOS: Check if system libhdhomerun works correctly
    # The Homebrew package may have incorrect install_name references where the
    # dylib's install_name doesn't match its actual filename (e.g., references
    # libhdhomerun_x64.dylib but file is libhdhomerun.dylib)
    HDHOMERUN_DYLIB := $(shell pkg-config --libs-only-L hdhomerun 2>/dev/null | sed 's/-L//')/libhdhomerun.dylib
    ifeq ($(HDHOMERUN_DYLIB),/libhdhomerun.dylib)
        # pkg-config didn't find it, try common Homebrew location
        HDHOMERUN_DYLIB := $(wildcard /usr/local/opt/libhdhomerun/lib/libhdhomerun.dylib)
    endif

    # Check if dylib exists and has matching install_name (empty result = broken)
    HDHOMERUN_OK := $(shell if [ -f "$(HDHOMERUN_DYLIB)" ]; then \
        install_name=$$(otool -D "$(HDHOMERUN_DYLIB)" 2>/dev/null | tail -1); \
        if [ "$$(basename "$$install_name")" = "libhdhomerun.dylib" ]; then echo "yes"; fi; \
    fi)

    ifeq ($(HDHOMERUN_OK),yes)
        # System libhdhomerun works, use it
        $(info Using system libhdhomerun)
        LDFLAGS = $(LIBS) -lhdhomerun
    else
        # System libhdhomerun is broken or missing, build from bundled sources
        $(info Building libhdhomerun from bundled sources (system library missing or has broken install_name))
        LIBHDHOMERUN = libhdhomerun/libhdhomerun.a
        LDFLAGS = $(LIBS) $(LIBHDHOMERUN)

        # libhdhomerun sources (macOS uses getifaddrs for interface detection)
        HDHOMERUN_SRCS = libhdhomerun/hdhomerun_channels.c \
                         libhdhomerun/hdhomerun_channelscan.c \
                         libhdhomerun/hdhomerun_control.c \
                         libhdhomerun/hdhomerun_debug.c \
                         libhdhomerun/hdhomerun_device.c \
                         libhdhomerun/hdhomerun_device_selector.c \
                         libhdhomerun/hdhomerun_discover.c \
                         libhdhomerun/hdhomerun_os_posix.c \
                         libhdhomerun/hdhomerun_pkt.c \
                         libhdhomerun/hdhomerun_sock.c \
                         libhdhomerun/hdhomerun_sock_posix.c \
                         libhdhomerun/hdhomerun_sock_getifaddrs.c \
                         libhdhomerun/hdhomerun_video.c
        HDHOMERUN_OBJS = $(HDHOMERUN_SRCS:.c=.o)
    endif
else
    # Linux: Use system libhdhomerun
    LDFLAGS = $(LIBS) -lhdhomerun
endif

# Source files
SRCS = a3render.c mmt.c input.c plp.c l1_detail_parser.c crypto.c esg.c bps.c utility.c direct_parsers.c

# Object files (automatically derived from SRCS)
OBJS = $(SRCS:.c=.o)

# Header files (for dependency tracking)
HEADERS = structures.h mmt.h input.h plp.h l1_detail_parser.h crypto.h esg.h bps.h utility.h direct_parsers.h

# Executable
TARGET = render

# Default target: build the executable
all: $(TARGET)

# Build the executable from object files
$(TARGET): $(OBJS) $(LIBHDHOMERUN)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Build static libhdhomerun for macOS (only when system library is broken)
ifdef LIBHDHOMERUN
$(LIBHDHOMERUN): $(HDHOMERUN_OBJS)
	$(AR) rcs $@ $^

libhdhomerun/%.o: libhdhomerun/%.c
	$(CC) -O2 -Wall -Wno-unused-parameter -c $< -o $@
endif

# Pattern rule for building object files from C source files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Target to clean up the build directory
clean:
	rm -f $(TARGET) $(OBJS)
ifdef LIBHDHOMERUN
	rm -f $(LIBHDHOMERUN) $(HDHOMERUN_OBJS)
endif

# Target to rebuild everything from scratch
rebuild: clean all

# Phony targets
.PHONY: all clean rebuild
