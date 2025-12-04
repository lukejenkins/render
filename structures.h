#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdbool.h>

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
    TABLE_TYPE_EFDT,
    TABLE_TYPE_MPD,
    TABLE_TYPE_MP_TABLE_XML,
    TABLE_TYPE_MP_TABLE_BINARY,
    TABLE_TYPE_MP_TABLE_PATTERN_MATCHED,
    TABLE_TYPE_HELD,
    TABLE_TYPE_ESG_FRAGMENT,
    TABLE_TYPE_SGDD,
    TABLE_TYPE_USER_SERVICE_DESCRIPTION,
    TABLE_TYPE_SERVICE_SIGNALING,
    TABLE_TYPE_STSID,
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

// For SLT: A single service entry
typedef struct ServiceInfo {
    char serviceId[16];
    char majorChannelNo[16];
    char minorChannelNo[16];
    char shortServiceName[64];
    char globalServiceID[128];
    char slsDestinationIpAddress[40];
    char slsDestinationUdpPort[16];
    char slsSourceIpAddress[40];
    char slsProtocol[8];
    char slsMmtpPacketId[16];
    char slsMajorProtocolVersion[8];
    char slsMinorProtocolVersion[8];
    char serviceCategory[8];
    char sltSvcSeqNum[8];
    int protected;
    int broadbandAccessRequired;
    int hidden;
    int hideInGuide;
    struct ServiceInfo* next;
} ServiceInfo;

// MMT media parameters
typedef struct {
    char resolution[32];
    char scan_type[16];
    char frame_rate[16];
    char audio_channels[16];
    char audio_codec[64];   // Increased for full codec strings like "ac-4.02.01.01.02.03"
    char video_codec[64];   // Increased for full codec strings like "hev1.2.3.L240.BA10"
    char hdr_wcg_info[32];
    int audio_bitrate_kbps;  // Bitrate in kbps (0 if unknown)
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

// Video Stream Properties Descriptor (VSPD) - A/331 Section 7.2.3.2
typedef struct {
    uint8_t codec_code;
    char codec_name[64];
    uint16_t horizontal_size;
    uint16_t vertical_size;
    uint8_t aspect_ratio;
    uint8_t frame_rate_code;
    char frame_rate[16];
    uint8_t color_depth;
    uint8_t  chroma_format;        // Chroma subsampling (0=mono, 1=4:2:0, 2=4:2:2, 3=4:4:4)
    uint8_t hdr_info;
    uint8_t profile_idc;
    char profile_name[64];
    uint8_t level_idc;
    float level_value;
    uint8_t tier_flag;
    uint8_t progressive_flag;
    uint8_t interlaced_flag;
} VspdData;

// Audio Stream Properties Descriptor (ASPD) - A/331 Section 7.2.3.4
typedef struct {
    uint8_t codec_code;
    char codec_name[64];
    uint8_t num_channels;
    uint32_t sample_rate;
    char channel_config[64];
    char language[64];
    uint8_t num_presentations;
} AspdData;

// Caption Asset Descriptor (CAD) - A/331 Section 7.2.3.5
typedef struct CadEntry {
    char language[64];
    uint8_t easy_reader;
    uint8_t wide_aspect_ratio;
    uint16_t service_number;
    uint8_t role;
    char role_str[32];
    uint8_t aspect_ratio;
    char aspect_str[16];
    uint8_t profile;
    char profile_str[16];
    uint8_t support_3d;
    struct CadEntry* next;
} CadEntry;

typedef struct {
    CadEntry* head;
} CadData;

// Storage for per-service descriptors
typedef struct ServiceDescriptors {
    char destinationIp[40];
    char destinationPort[16];
    VspdData* vspd;
    AspdData* aspd;
    CadData* cad;
} ServiceDescriptors;

typedef struct {
    uint8_t version;
    uint8_t packet_counter_flag;
    uint8_t fec_type;
    uint8_t extension_flag;
    uint8_t rap_flag;
    uint8_t qos_flag;
    uint16_t packet_id;
    uint32_t timestamp;
    uint32_t packet_sequence_number;
    uint16_t packet_counter;
    uint8_t qos_classifier;
    uint8_t payload_type;
    uint32_t payload_length;
    uint16_t extension_type;
    uint16_t extension_length;
    uint8_t* extension_data;
} mmt_packet_header_t;

// MPU header structure
typedef struct {
    uint32_t mpu_sequence_number;
    uint8_t fragmentation_indicator;
    uint8_t fragment_type;
    const uint8_t* mfu_data;
    size_t mfu_data_length;
} MpuHeader;

// For MMT-specific USD data (BundleDescriptionMMT)
typedef struct UsdEntryMmt {
    char id[128];
    char contentType[128];
    char version[16];
    struct UsdEntryMmt* next;
} UsdEntryMmt;

typedef struct {
    UsdEntryMmt* head;
} UsdbData;

// For MMT MP Table
typedef struct MptAsset {
    char assetId[256];
    char assetType[64];
    char packetId[16];
    struct MptAsset* next;
} MptAsset;

typedef struct {
    char mptPackageId[256];
    MptAsset* head_asset;
} MpTableData;

typedef struct BinaryMptAsset {
    char assetId[256];
    char assetType[64];
    char codec[64];
    uint16_t packetId;
    struct BinaryMptAsset* next;
} BinaryMptAsset;

typedef struct {
    BinaryMptAsset* head_asset;
} BinaryMptData;

typedef struct {
    char asset_id[128];
    char asset_type[5];      // FourCC like "hvc1", "ac-4"
    uint16_t packet_id;
    bool is_default;
    uint32_t asset_id_scheme;  // 0=UUID, 1=URI
} MptAssetInfo;

typedef struct {
    char package_id[128];
    uint8_t version;
    uint8_t table_id;
    uint8_t num_assets;
    MptAssetInfo assets[32];
    char source_ip[64];
    char source_port[16];
    time_t last_updated;
    bool is_complete;
} MptTable;

// For USD (User Service Description)
typedef struct UsdAsset {
    char assetId[128];
    char assetType[64];
    char role[64];
    char lang[16];
    struct UsdAsset* next;
} UsdAsset;

typedef struct UsdComponent {
    char componentId[128];
    int componentType;
    int componentRole;
    char description[256];
    struct UsdComponent* next;
} UsdComponent;

typedef struct UsdData {
    char serviceId[64];
    char serviceName[256];
    char serviceDescription[512];
    char serviceCategory[16];
    char globalServiceId[128];
    char mmtPackageId[128];
    UsdComponent* components;
    UsdAsset* assets;
} UsdData;

typedef struct {
    uint16_t message_id;
    int count;
    int parsed_count;
    char first_seen_ip[64];
    char first_seen_port[16];
} MmtMessageStats;

#endif // STRUCTURES_H
