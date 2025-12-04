#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>

// Maximum limits
#define MAX_PAYLOAD_SIZE 65536
#define MAX_TABLES 100000
#define MAX_SERVICES 5000
#define MAX_UNIQUE_PIDS 2000
#define MAX_DATA_STREAMS 1000

// Table type enumeration
typedef enum {
    TABLE_TYPE_UNKNOWN,
    TABLE_TYPE_SLT,
    TABLE_TYPE_SYSTEM_TIME,
    TABLE_TYPE_UCT,
    TABLE_TYPE_CDT,
    TABLE_TYPE_UDST,
    TABLE_TYPE_SIGNATURE,
    TABLE_TYPE_FDT,
    TABLE_TYPE_MPD,
    TABLE_TYPE_HELD,
    TABLE_TYPE_ESG_FRAGMENT,
    TABLE_TYPE_SGDD,
    TABLE_TYPE_USER_SERVICE_DESCRIPTION,
    TABLE_TYPE_SERVICE_SIGNALING,
    TABLE_TYPE_STSID,
    TABLE_TYPE_MP_TABLE_XML,
    TABLE_TYPE_MP_TABLE_BINARY,
    TABLE_TYPE_MP_TABLE_PATTERN_MATCHED,
    TABLE_TYPE_USBD,
    TABLE_TYPE_USD,
    TABLE_TYPE_DWD,
    TABLE_TYPE_LMT
} TableType;

// Service destination structure
typedef struct {
    struct in_addr ip_addr;
    uint16_t port;
    char destinationIpStr[40];
    char destinationPortStr[16];
    char protocol[8];
    uint16_t mmtSignalingPacketId;
    char serviceCategory[8];
    int isEsgService;
} ServiceDestination;

// Data usage tracking
typedef struct DataUsageEntry {
    char destinationIp[40];
    char destinationPort[16];
    uint32_t tsi_or_packet_id;
    uint64_t total_bytes;
    uint32_t packet_count;
    char description[128];
    char stream_type[16];
    int is_lls;
    int is_signaling;
} DataUsageEntry;

// Packet ID logging
typedef struct {
    uint16_t id;
    int count;
} PacketIdLog;

// MMT media parameters
typedef struct {
    char resolution[32];
    char scan_type[16];
    char frame_rate[16];
    char audio_channels[16];
    char audio_codec[32];
    char video_codec[32];
} MmtMediaParams;

typedef struct {
    char destIp[40];
    char destPort[16];
    uint16_t packet_id;
    MmtMediaParams params;
} MmtMediaParamsCache;

// Generic table storage
typedef struct {
    char* content_id;
    void* parsed_data;
    TableType type;
    char destinationIp[40];
    char destinationPort[16];
} LlsTable;

#endif // STRUCTURES_H
