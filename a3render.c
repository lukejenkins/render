/******************************************************************************
 * render.c
 * 
 * RENDER = RabbitEars NextGen Data Evaluator and Reporter
 *
 * An ATSC 3.0 LLS and ROUTE/DASH Signaling parser.
 *
 * This tool reads an ATSC 3.0 PCAP file, finds UDP packets containing LLS
 * and ROUTE data, decompresses gzipped XML payloads, and parses the XML to

 * generate a human-readable HTML report.
 *
 * Author: Gemini
 *
 *****************************************************************************/
#define _GNU_SOURCE // For memmem
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <zlib.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <ctype.h>
#include <stdarg.h>
#include <math.h>
#include <sys/stat.h>
#include <time.h>
#include <stdbool.h>

#include "structures.h"
#include "input.h"
#include "plp.h"
#include "l1_detail_parser.h"
#include "crypto.h"
#include "esg.h"
#include "bps.h"
#include "utility.h"

// --- To enable verbose MMT packet debugging, set to 1 ---
#define DEBUG_MMT 0

// MMT packet types
#define MMT_PACKET_TYPE_IPV4 0x0
#define MMT_PACKET_TYPE_IPV6 0x1
#define MMT_PACKET_TYPE_GFP  0x2
#define MMT_PACKET_TYPE_HEADER_COMPRESSION 0x3

// MMT payload types
#define MMT_PAYLOAD_TYPE_MPU 0x0
#define MMT_PAYLOAD_TYPE_GENERIC_OBJECT 0x1
#define MMT_PAYLOAD_TYPE_SIGNALING_MESSAGE 0x2

// LMT specific constants
#define LMT_TABLE_ID 0x01

// Enhanced LMT structures to store multicast destination info
typedef struct LmtMulticast {
    uint32_t src_ip;
    uint32_t dest_ip;
    uint16_t src_port;
    uint16_t dest_port;
    uint8_t sid_bit;
    uint8_t compression_bit;
    char dest_ip_str[16];
    char dest_port_str[8];
    struct LmtMulticast* next;
} LmtMulticast;

typedef struct LmtService {
    uint8_t service_id;
    uint8_t service_category;
    uint16_t plp_id;
    char service_name[64];
    LmtMulticast* multicasts;
    struct LmtService* next;
} LmtService;

typedef struct {
    uint8_t lmt_version;
    uint8_t num_services;
    LmtService* services;
} LmtData;

// --- Data Structures for Parsed XML ---
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

// For SLT: Holds the list of all services
typedef struct {
    char bsid[16];
    ServiceInfo* head;
} SltData;

typedef struct {
    char currentUtcOffset[16];
    char ptpPrepend[16];
    char leap59[16];
    char leap61[16];
    char utcLocalOffset[16];
    char dsStatus[16];
    char dsDayOfMonth[16];
    char dsHour[16];
} SystemTimeData;

// For UCT: A single package element
typedef struct NdElement {
    char name[128];
    char tsi[16];
    struct NdElement* next;
} NdElement;

// For UCT: A single package
typedef struct NdPackage {
    char name[128];
    char dstIP[40];
    char dstPort[16];
    NdElement* head_element;
    struct NdPackage* next;
} NdPackage;

// For UCT: Holds the list of all packages
typedef struct {
    NdPackage* head_package;
} UctData;

// For UDST: a single reservation entry
typedef struct RsrvInfo {
    char name[64];
    char srvid[16];
    char destIP[40];
    char destPort[16];
    char orderId[128];
    struct RsrvInfo* next;
} RsrvInfo;

// For UDST: a single BroadSpan service
typedef struct BroadSpanServiceInfo {
    char name[128];
    RsrvInfo* head_rsrv;
    struct BroadSpanServiceInfo* next;
} BroadSpanServiceInfo;

// For UDST: Top-level container
typedef struct {
    char version[16];
    BroadSpanServiceInfo* head_service;
} UdstData;

// For SMT Signature blocks
typedef struct {
    int signature_len;
} SignatureData;

// For FDT: A single file entry
typedef struct FDTFileInfo {
    char contentLocation[256];
    char toi[16];
    char contentLength[16];
    char contentType[64];
    struct FDTFileInfo* next;
} FDTFileInfo;

// For FDT: Top-level container
typedef struct {
    char expires[32];
    FDTFileInfo* head;
} FDTInstanceData;

// For MPD: A single S element from a SegmentTimeline
typedef struct SegmentTimelineS {
    char t[32];
    char d[32];
    char r[16];
    struct SegmentTimelineS* next;
} SegmentTimelineS;

// For MPD: Segment template information
typedef struct {
    char initialization[256];
    char media[256];
    char timescale[32];
    char startNumber[16];
    char duration[32];
    SegmentTimelineS* timeline;
} SegmentTemplateData;

// For MPD: A single media representation (e.g., one quality level of video)
typedef struct MpdRepresentation {
    char id[64];
    char codecs[128];
    char bandwidth[32];
    char width[16];
    char height[16];
    char frameRate[16];
    char audioSamplingRate[16];
    char sar[16];
    char scanType[32];
    char audioChannelCount[16];
    char displayAspectRatio[16];
    DrmInfo* drmInfo;  
    SegmentTemplateData segmentTemplate;
    struct MpdRepresentation* next;
} MpdRepresentation;

// For MPD: A set of adaptable media representations (e.g., all video tracks)
typedef struct MpdAdaptationSet {
    char contentType[64];
    char lang[16];
    char mimeType[64];
    char par[16]; // pixel aspect ratio
    MpdRepresentation* head_rep;
    struct MpdAdaptationSet* next;
} MpdAdaptationSet;

// For MPD: Top-level container
typedef struct {
    char publishTime[64];
    char profiles[256];
    char type[32];
    char minBufferTime[32];
    MpdAdaptationSet* head_as;
} MpdData;

// Enhanced MPT structures
typedef struct MptAssetDescriptor {
    uint8_t descriptor_tag;
    uint8_t descriptor_length;
    uint8_t* descriptor_data;
    struct MptAssetDescriptor* next;
} MptAssetDescriptor;

typedef struct MptAssetLocation {
    uint8_t location_type;
    uint16_t packet_id;
    struct MptAssetLocation* next;
} MptAssetLocation;

typedef struct MptAssetInfo {
    char asset_id[256];
    uint8_t asset_id_length;
    char asset_type[64];
    uint8_t asset_type_length;
    uint8_t asset_clock_relation_flag;
    uint8_t location_count;
    MptAssetLocation* locations;
    uint8_t descriptor_count;
    MptAssetDescriptor* descriptors;
    struct MptAssetInfo* next;
} MptAssetInfo;

typedef struct MptMessageData {
    uint8_t table_id;
    uint8_t version;
    uint16_t length;
    uint16_t mmt_package_id_length;
    char mmt_package_id[256];
    uint8_t mpt_mode;
    uint8_t mpu_timestamp_descriptor;
    uint8_t num_of_assets;
    MptAssetInfo* assets;
    uint8_t descriptor_count;
    MptAssetDescriptor* descriptors;
} MptMessageData;

typedef struct {
    char bbandEntryPageUrl[512];
    char clearBbandEntryPageUrl[512];
    char coupledServices[128];
} HeldData;

// For BundleDescriptionROUTE (User Service Description)
typedef struct UsdEntry {
    char contentType[128];
    char version[16];
    char userAgent[128];
    char filterCodes[128];
    struct UsdEntry* next;
} UsdEntry;

typedef struct {
    UsdEntry* head;
} UserServiceDescriptionData;

// --- For BundleDescriptionMMT ---
typedef struct UsdEntryMmt {
    char id[128];
    char contentType[128];
    char version[16];
    struct UsdEntryMmt* next;
} UsdEntryMmt;

typedef struct {
    UsdEntryMmt* head;
} UsdbData;

typedef struct UsdAsset {
    char assetId[128];
    char assetType[64];  // "video", "audio", "data", etc.
    char role[64];       // "main", "alternate", "supplementary"
    char lang[16];       // Language code
    struct UsdAsset* next;
} UsdAsset;

typedef struct UsdComponent {
    char componentId[128];
    int componentType;    // 0=audio, 1=video, 2=data
    int componentRole;    // 0=main, 1=alternate, etc.
    char description[256]; // Derived description
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

// For metadataEnvelope (Service Signaling)
typedef struct ServiceSignalingFragment {
    char contentType[128];
    char version[16];
    struct ServiceSignalingFragment* next;
} ServiceSignalingFragment;

typedef struct {
    ServiceSignalingFragment* head;
} ServiceSignalingData;

// For S-TSID: a single content rating
typedef struct ContentRatingInfo {
    char value[256];
    struct ContentRatingInfo* next;
} ContentRatingInfo;

// For S-TSID: a single logical stream
typedef struct StsidLogicalStream {
    char tsi[16];
    char repId[64];
    char contentType[64];
    ContentRatingInfo* head_rating;
    struct StsidLogicalStream* next;
} StsidLogicalStream;

typedef struct {
    char dIpAddr[40];
    char dPort[16];
    StsidLogicalStream* head_ls;
} StsidData;

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

typedef struct DwdData {
    char placeholder[32]; // Not fully parsed, just acknowledged
} DwdData;

// Struct to buffer ROUTE object fragments
typedef struct ReassemblyBuffer {
    uint32_t toi; // For ROUTE, this is TOI; for MMT, this is TOI from ALC
    uint32_t tsi; 
    int mmt_header_len;
    uint8_t* buffer;
    size_t size;
    char destinationIp[40];
    char destinationPort[16];
    struct ReassemblyBuffer* next;
} ReassemblyBuffer;

typedef struct {
    uint8_t version;
    uint8_t packet_counter_flag;
    uint8_t fec_type;
    uint8_t extension_flag;
    uint8_t rap_flag;
    uint16_t packet_id;
    uint32_t timestamp;
    uint32_t packet_sequence_number;
    uint16_t packet_counter;
    
    // Payload information
    uint8_t payload_type;
    uint32_t payload_length;
    
    // Header extensions if present
    uint16_t extension_type;
    uint16_t extension_length;
    uint8_t* extension_data;
} mmt_packet_header_t;

// MMT signaling message types
#define MMT_SIGNALING_PA_MESSAGE 0x0000
#define MMT_SIGNALING_MPI_MESSAGE 0x0001
#define MMT_SIGNALING_MPT_MESSAGE 0x0002
#define MMT_SIGNALING_CRI_MESSAGE 0x0003
#define MMT_SIGNALING_DCI_MESSAGE 0x0004
#define MMT_SIGNALING_SSWR_MESSAGE 0x0005
#define MMT_SIGNALING_AL_FEC_MESSAGE 0x0006
#define MMT_SIGNALING_HRBM_MESSAGE 0x0007
#define MMT_SIGNALING_MC_MESSAGE 0x0008
#define MMT_SIGNALING_AC_MESSAGE 0x0009
#define MMT_SIGNALING_AF_MESSAGE 0x000A
#define MMT_SIGNALING_RQF_MESSAGE 0x000B
#define MMT_SIGNALING_ADC_MESSAGE 0x000C
#define MMT_SIGNALING_HRB_REMOVAL_MESSAGE 0x000D
#define MMT_SIGNALING_LS_MESSAGE 0x000E
#define MMT_SIGNALING_LR_MESSAGE 0x000F
#define MMT_SIGNALING_NAMF_MESSAGE 0x0010
#define MMT_SIGNALING_LDC_MESSAGE 0x0011

// Enhanced MMT signaling message structure
typedef struct {
    uint16_t message_id;
    uint8_t version;
    uint32_t length;
    uint8_t* payload;
} mmt_signaling_message_t;

// New structure for this proprietary MPT format
typedef struct ProprietaryMptAsset {
    uint32_t asset_id_length;
    char asset_id[256];
    uint16_t packet_id;
    char codec[64];
    char asset_type[64];
    struct ProprietaryMptAsset* next;
} ProprietaryMptAsset;

typedef struct ProprietaryMptData {
    uint8_t table_id;
    uint8_t version;
    uint16_t length;
    char package_descriptor[256];
    uint8_t num_assets;
    ProprietaryMptAsset* assets;
} ProprietaryMptData;

// MPU header structure
typedef struct {
    uint32_t mpu_sequence_number;
    uint8_t fragmentation_indicator;
    uint8_t fragment_type;
    const uint8_t* mfu_data;
    size_t mfu_data_length;
} MpuHeader;

// --- Global Variables ---
static int g_packet_count = 0;
static int g_link_type;
static LlsTable g_lls_tables[MAX_TABLES];
static int g_lls_table_count = 0;
static ServiceDestination g_service_dests[MAX_SERVICES];
static int g_service_dest_count = 0;
static ReassemblyBuffer* g_reassembly_head = NULL;
static char g_input_filename[512] = "";
static int g_input_type = INPUT_TYPE_PCAP;
static struct timeval g_first_packet_time = {0, 0};
static struct timeval g_last_packet_time = {0, 0};
static int g_pcap_timing_valid = 0;
static DataUsageEntry g_data_usage[MAX_DATA_STREAMS];
static int g_data_usage_count = 0;
static uint64_t g_total_capture_bytes = 0;
static BpsData* g_bps_data = NULL;

// --- Global variables for MMT Packet ID logging ---
static PacketIdLog g_packet_id_log[MAX_UNIQUE_PIDS];
static int g_packet_id_log_count = 0;
static bool packet_id_seen[65536] = {false}; // Track first occurrence of each packet ID
static MmtMediaParamsCache g_mmt_params_cache[100];
static int g_mmt_params_cache_count = 0;

// --- Function Prototypes ---
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void process_lls_payload(const u_char *payload, int len);
void process_route_payload(const u_char* payload, int len, const char* destIp, const char* destPort);
uint16_t get_route_header_length(const u_char* payload, int len);
uint16_t get_route_payload_offset(const u_char* payload, int len);
void process_mime_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* boundary_str, const char* destIp, const char* destPort);
void process_terminal_payload(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort, int is_mmt, uint16_t packet_id);
void process_and_store_route_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort);
void store_slt_destinations(SltData* slt_data);
char* decompress_gzip(const u_char *compressed_data, int len, int *decompressed_size, int* consumed_size);
void store_unique_table(const char* content, int len, TableType type, void* parsed_data, const char* destIp, const char* destPort);
void generate_html_report(const char* filename);
int is_gzip_complete(const uint8_t* buffer, size_t size);
int is_xml_complete(const char* buffer, size_t size);
void process_mmt_signaling_payload(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort);
void cleanup();

void log_mmt_packet_id(uint16_t packet_id);
void print_packet_id_log();

BinaryMptData* parse_binary_mp_table_multiformat(const uint8_t* buffer, size_t size);
int parse_mmt_packet_header(const uint8_t* buffer, size_t length, mmt_packet_header_t* header);
int parse_mmt_signaling_message(const uint8_t* buffer, size_t length, mmt_signaling_message_t* message);
void process_mmt_signaling_message(mmt_signaling_message_t* message, const char* destIp, const char* destPort);
void free_mmt_packet_header(mmt_packet_header_t* header);
void process_enhanced_mmt_payload(const u_char* payload, int len, ServiceDestination* dest_info);
void process_enhanced_mmt_signaling_payload(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort);
BinaryMptData* parse_enhanced_binary_mp_table(const uint8_t* buffer, size_t size);
void free_mpt_message_data(MptMessageData* mpt);
void free_proprietary_mpt_data(ProprietaryMptData* mpt);

void process_multi_document_xml(const char* xml_data, size_t size, const char* destIp, const char* destPort, const char* source_id);
void remove_functionally_duplicate_tables();
int is_truncated_duplicate(const char* content1, const char* content2);
const char* get_enhanced_stream_description(const char* dest_ip, const char* dest_port, 
                                          uint32_t tsi_or_packet_id, const char* stream_type, int is_lls);
int compare_data_usage_by_bytes(const void *a, const void *b);
const char* get_media_type_from_stsid(const char* dest_ip, const char* dest_port, uint32_t tsi);
const char* get_media_type_from_mpt(const char* dest_ip, const char* dest_port, uint32_t packet_id);
const char* get_extended_stream_description(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type);
const char* get_service_name_for_destination(const char* dest_ip, const char* dest_port);
int is_likely_route_packet(const uint8_t* payload, int len);
int is_likely_mmt_packet(const uint8_t* payload, int len);
int is_likely_rtp_packet(const uint8_t* payload, int len);
const char* infer_content_type_from_context(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type);
void reclassify_data_usage_after_slt();
void consolidate_data_usage_entries();
int has_lmt_data(void);
int get_plps_for_service_enhanced(const char* dest_ip, const char* dest_port, char* plp_list, size_t plp_list_size);

// XML parsing functions
int parse_xml(const char* xml_content, int len, TableType* type, void** parsed_data_out, const char* source_identifier);
SltData* parse_slt(xmlDocPtr doc);
SystemTimeData* parse_system_time(xmlDocPtr doc);
UctData* parse_uct(xmlDocPtr doc);
UdstData* parse_udst(xmlDocPtr doc);
FDTInstanceData* parse_fdt(xmlDocPtr doc);
FDTInstanceData* parse_fdt_from_node(xmlNodePtr fdt_node);
void parse_embedded_children(xmlNodePtr parent_node, const char* destIp, const char* destPort);
StsidData* parse_stsid(xmlDocPtr doc);
MpdData* parse_mpd(xmlDocPtr doc);
HeldData* parse_held(xmlDocPtr doc);
UserServiceDescriptionData* parse_user_service_description(xmlDocPtr doc);
char* extract_node_as_xml(xmlNodePtr node);
UsdbData* parse_usbd(xmlDocPtr doc);
UsdData* parse_usd(xmlDocPtr doc);
DwdData* parse_dwd(xmlDocPtr doc);
ServiceSignalingData* parse_service_signaling(xmlDocPtr doc);
MpTableData* parse_mp_table(xmlDocPtr doc);
int is_esg_service(const char* destIp, const char* destPort);
int is_bps_service(const char* destIp, const char* destPort);
int normalize_xml_content(const char* xml_content, char* normalized_buffer, size_t buffer_size);
char* normalize_xml_declaration(const char* xml_content);
int is_functionally_equivalent(const char* content1, const char* content2);

// Cleanup functions for parsed data
void free_parsed_data(LlsTable* table);
void free_slt_data(SltData* data);
void free_uct_data(UctData* data);
void free_udst_data(UdstData* data);
void free_fdt_data(FDTInstanceData* data);
void free_mpd_data(MpdData* data);
void free_held_data(HeldData* data);
void free_user_service_description_data(UserServiceDescriptionData* data);
void free_usbd_data(UsdbData* data);
void free_usd_data(UsdData* data);
void free_service_signaling_data(ServiceSignalingData* data);
void free_stsid_data(StsidData* data);
void free_mp_table_data(MpTableData* data);
void free_binary_mp_table_data(BinaryMptData* data);
void free_reassembly_buffers();

// --- Main Function ---
int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file_or_debug_file>\n", argv[0]);
        fprintf(stderr, "\nSupported file types:\n");
        fprintf(stderr, "  .pcap/.pcapng - Standard PCAP capture files\n");
        fprintf(stderr, "  .dbg - ATSC 3.0 debug files\n");
        fprintf(stderr, "  ALP-PCAP files (detected by filename containing 'alp')\n");
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    uint8_t *virtual_pcap_data = NULL;
    size_t virtual_pcap_size = 0;
    int input_type = detect_file_type(argv[1]);
    
    if (input_type == INPUT_TYPE_DEBUG) {
        printf("Detected debug file format: %s\n", argv[1]);
        
        // Convert debug file to virtual PCAP
        if (create_virtual_pcap_from_debug(argv[1], &virtual_pcap_data, &virtual_pcap_size) != 0) {
            fprintf(stderr, "Error processing debug file\n");
            return 1;
        }
        
        // Open virtual PCAP from memory
        handle = pcap_open_offline_with_tstamp_precision(
            (char*)virtual_pcap_data, PCAP_TSTAMP_PRECISION_MICRO, errbuf);
        if (handle == NULL) {
            // Try opening as memory buffer (if supported)
            handle = pcap_open_dead(DLT_EN10MB, 65535);
            if (handle == NULL) {
                fprintf(stderr, "Error creating virtual PCAP handle: %s\n", errbuf);
                free(virtual_pcap_data);
                return 1;
            }
        }
        
        printf("Successfully converted debug file to virtual PCAP\n");
        
    } else {
        printf("Opening %s file: %s\n", 
               (input_type == INPUT_TYPE_ALP_PCAP) ? "ALP-PCAP" : "PCAP", 
               argv[1]);
        handle = pcap_open_offline(argv[1], errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Error opening PCAP file: %s\n", errbuf);
            return 1;
        }
    }
    
    strncpy(g_input_filename, argv[1], sizeof(g_input_filename) - 1);
    g_input_filename[sizeof(g_input_filename) - 1] = '\0';
    g_input_type = input_type;
    
    // Check for and parse optional L1 signaling file
    char* txt_filename = get_txt_filename_from_input(argv[1]);
    if (txt_filename) {
        set_enhanced_l1_signaling_data(parse_enhanced_l1_signaling_file(txt_filename));
        free(txt_filename);
    }

    // Determine the link-layer header type
    g_link_type = pcap_datalink(handle);
    switch (g_link_type) {
        case DLT_EN10MB:
            printf("Link-type: Ethernet (DLT_EN10MB)\n\n");
            break;
        case DLT_IPV4:
            printf("Link-type: Raw IPv4 (DLT_IPV4)\n\n");
            break;
        case DLT_ATSC_ALP:
            printf("Link-type: ATSC ALP (DLT_ATSC_ALP)\n\n");
            g_input_type = INPUT_TYPE_ALP_PCAP; // Override input type detection
            break;
        default:
            fprintf(stderr, "Unsupported link-type: %d. Only Ethernet, Raw IPv4, and ATSC ALP are supported.\n", g_link_type);
            pcap_close(handle);
            if (virtual_pcap_data) free(virtual_pcap_data);
            return 1;
    }

    // Initialize the tables array
    for (int i = 0; i < MAX_TABLES; i++) {
        g_lls_tables[i].content_id = NULL;
        g_lls_tables[i].parsed_data = NULL;
        g_lls_tables[i].type = TABLE_TYPE_UNKNOWN;
        g_lls_tables[i].destinationIp[0] = '\0';
        g_lls_tables[i].destinationPort[0] = '\0';
    }
    
    // Initialize libxml2
    LIBXML_TEST_VERSION

    // For debug files, we need to manually process the virtual PCAP data
    if (input_type == INPUT_TYPE_DEBUG) {
        printf("Processing virtual PCAP data from debug file...\n");
        
        // Process the virtual PCAP data manually
        const uint8_t *data = virtual_pcap_data + 24; // Skip global header
        size_t remaining = virtual_pcap_size - 24;
        
        while (remaining > 16) { // Need at least record header
            // Read record header
            uint32_t ts_sec = *(uint32_t*)data;
            uint32_t ts_usec = *(uint32_t*)(data + 4);
            uint32_t incl_len = *(uint32_t*)(data + 8);
            uint32_t orig_len = *(uint32_t*)(data + 12);
            
            data += 16;
            remaining -= 16;
            
            if (remaining < incl_len) break;
            
            // Create a fake pcap_pkthdr for compatibility
            struct pcap_pkthdr pkthdr;
            pkthdr.ts.tv_sec = ts_sec;
            pkthdr.ts.tv_usec = ts_usec;
            pkthdr.caplen = incl_len;
            pkthdr.len = orig_len;
            
            // Process this packet
            packet_handler(NULL, &pkthdr, data);
            
            data += incl_len;
            remaining -= incl_len;
        }
        
    } else {
        // Loop through packets normally for PCAP files
        pcap_loop(handle, 0, packet_handler, NULL);
    }

    // --- Process any remaining open (incomplete) ROUTE/MMT objects ---

    ReassemblyBuffer* current_buf = g_reassembly_head;
    int buffer_count = 0;
    while(current_buf != NULL) {
        buffer_count++;
        
        // Skip buffers that are too small (likely just a header fragment)
        if (current_buf->size < 100) {
            //printf("   Skipping - buffer too small (< 100 bytes)\n");
            current_buf = current_buf->next;
            continue;
        }
        
        // Check if buffer looks complete despite missing close flag
        // If it has MIME boundaries and looks complete, skip it
        if (memmem(current_buf->buffer, current_buf->size, "multipart/related", 17)) {
            // Check if it has final boundary marker
            const char* boundary_marker = "boundary=\"";
            const uint8_t* boundary_loc = memmem(current_buf->buffer, 
                current_buf->size > 500 ? 500 : current_buf->size, 
                boundary_marker, strlen(boundary_marker));
            
            if (boundary_loc) {
                current_buf = current_buf->next;
                continue;
            }
        }
        
        // Skip buffers that don't look like they contain useful data
        // Check if it starts with something recognizable
        int looks_valid = 0;
        if (current_buf->size > 5) {
            if (memcmp(current_buf->buffer, "<?xml", 5) == 0 ||
                memcmp(current_buf->buffer, "<MPD", 4) == 0 ||
                memcmp(current_buf->buffer, "<S-TSID", 7) == 0 ||
                memcmp(current_buf->buffer, "Content-Type:", 13) == 0 ||
                (current_buf->buffer[0] == 0x1f && current_buf->buffer[1] == 0x8b)) { // gzip
                looks_valid = 1;
            }
        }
        
        if (!looks_valid) {
            current_buf = current_buf->next;
            continue;
        }
        
        int is_route = 0;
        for(int i=0; i< g_service_dest_count; i++) {
            if(strcmp(g_service_dests[i].destinationIpStr, current_buf->destinationIp) == 0 &&
            strcmp(g_service_dests[i].destinationPortStr, current_buf->destinationPort) == 0 &&
            strcmp(g_service_dests[i].protocol, "1") == 0) {
                is_route = 1;
                break;
            }
        }
        
        if (is_route) {
            process_and_store_route_object(current_buf->toi, current_buf->buffer, current_buf->size, 
                                        current_buf->destinationIp, current_buf->destinationPort);
        } else {
            process_mmt_signaling_payload(current_buf->buffer, current_buf->size, 
                                        current_buf->destinationIp, current_buf->destinationPort);
        }
        current_buf = current_buf->next;
    }

    // --- Generate Report Filename ---
    char output_filename[256];
    strncpy(output_filename, argv[1], sizeof(output_filename) - 1);
    output_filename[sizeof(output_filename) - 1] = '\0'; // Ensure null termination

    char *dot = strrchr(output_filename, '.');
    if (dot != NULL) {
        strcpy(dot, ".html");
    } else {
        strncat(output_filename, ".html", sizeof(output_filename) - strlen(output_filename) - 1);
    }

    printf("\nFinished processing %s file.\n", (input_type == INPUT_TYPE_DEBUG) ? "debug" : "PCAP");
    print_packet_id_log();

    reclassify_data_usage_after_slt();
    
    // ESG processing
    for (int i = 0; i < g_service_dest_count; i++) {
        if (g_service_dests[i].isEsgService) {
            correlate_esg_fragments(g_service_dests[i].destinationIpStr, 
                                g_service_dests[i].destinationPortStr,
                                g_lls_tables, g_lls_table_count);
        }
    }

    remove_functionally_duplicate_tables();
    generate_html_report(output_filename);
    
    // Free L1 signaling data if it exists
    if (get_l1_signaling_data()) {
        free_l1_signaling_data(get_l1_signaling_data());
        set_l1_signaling_data(NULL);
    }

    // Cleanup
    pcap_close(handle);
    if (virtual_pcap_data) free(virtual_pcap_data);
    cleanup();
    xmlCleanupParser();

    return 0;
}

void record_data_usage(const char* dest_ip, const char* dest_port, uint32_t tsi_or_packet_id, 
                      uint32_t packet_bytes, const char* description) {
    g_total_capture_bytes += packet_bytes;
    
    // Find existing entry or create new one
    DataUsageEntry* entry = NULL;
    for (int i = 0; i < g_data_usage_count; i++) {
        if (strcmp(g_data_usage[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_data_usage[i].destinationPort, dest_port) == 0 &&
            g_data_usage[i].tsi_or_packet_id == tsi_or_packet_id) {
            entry = &g_data_usage[i];
            break;
        }
    }
    
    if (!entry && g_data_usage_count < MAX_DATA_STREAMS) {
        entry = &g_data_usage[g_data_usage_count];
        strncpy(entry->destinationIp, dest_ip, sizeof(entry->destinationIp) - 1);
        entry->destinationIp[sizeof(entry->destinationIp) - 1] = '\0';
        strncpy(entry->destinationPort, dest_port, sizeof(entry->destinationPort) - 1);
        entry->destinationPort[sizeof(entry->destinationPort) - 1] = '\0';
        entry->tsi_or_packet_id = tsi_or_packet_id;
        entry->total_bytes = 0;
        entry->packet_count = 0;
        strncpy(entry->description, description, sizeof(entry->description) - 1);
        entry->description[sizeof(entry->description) - 1] = '\0';
        entry->is_lls = (strcmp(dest_ip, "224.0.23.60") == 0 && strcmp(dest_port, "4937") == 0);
        
        // Determine stream type and signaling flag
        if (entry->is_lls) {
            strcpy(entry->stream_type, "LLS");
            entry->is_signaling = 1;
        } else if (strstr(description, "ROUTE")) {
            strcpy(entry->stream_type, "ROUTE");
            entry->is_signaling = (tsi_or_packet_id == 0);
        } else if (strstr(description, "MMT")) {
            strcpy(entry->stream_type, "MMT");
            entry->is_signaling = (strstr(description, "Signaling") != NULL);
        } else {
            strcpy(entry->stream_type, "Other UDP");
            entry->is_signaling = 0;
        }
        
        g_data_usage_count++;
    }
    
    if (entry) {
        entry->total_bytes += packet_bytes;
        entry->packet_count++;
    }
}

// Function to get description for a stream
const char* get_stream_description(const char* dest_ip, const char* dest_port, uint32_t tsi) {
    // Check if it's LLS
    if (strcmp(dest_ip, "224.0.23.60") == 0 && strcmp(dest_port, "4937") == 0) {
        return "ATSC 3.0 LLS (Low Level Signaling)";
    }
    
    // Check if it's a known service stream
    for (int i = 0; i < g_service_dest_count; i++) {
        if (strcmp(g_service_dests[i].destinationIpStr, dest_ip) == 0 &&
            strcmp(g_service_dests[i].destinationPortStr, dest_port) == 0) {
            
            // Find service name from SLT
            for (int j = 0; j < g_lls_table_count; j++) {
                if (g_lls_tables[j].type == TABLE_TYPE_SLT) {
                    SltData* slt_data = (SltData*)g_lls_tables[j].parsed_data;
                    ServiceInfo* service = slt_data->head;
                    while (service) {
                        if (strcmp(service->slsDestinationIpAddress, dest_ip) == 0 &&
                            strcmp(service->slsDestinationUdpPort, dest_port) == 0) {
                            
                            static char desc[128];
                            if (tsi == 0) {
                                snprintf(desc, sizeof(desc), "%s - Signaling (TSI 0)", 
                                        service->shortServiceName);
                            } else {
                                snprintf(desc, sizeof(desc), "%s - Media (TSI %u)", 
                                        service->shortServiceName, tsi);
                            }
                            return desc;
                        }
                        service = service->next;
                    }
                }
            }
            
            // Fallback description
            static char fallback[128];
            if (tsi == 0) {
                snprintf(fallback, sizeof(fallback), "Service Signaling (TSI 0)");
            } else {
                snprintf(fallback, sizeof(fallback), "Service Media (TSI %u)", tsi);
            }
            return fallback;
        }
    }
    
    // Unknown stream
    static char unknown[128];
    if (tsi == 0) {
        snprintf(unknown, sizeof(unknown), "Unknown Stream - Signaling");
    } else {
        snprintf(unknown, sizeof(unknown), "Unknown Stream - TSI %u", tsi);
    }
    return unknown;
}

void update_packet_timing(const struct pcap_pkthdr *pkthdr) {
    if (g_input_type == INPUT_TYPE_PCAP) {
        if (g_packet_count == 1) {
            // First packet
            g_first_packet_time = pkthdr->ts;
            g_last_packet_time = pkthdr->ts;
            g_pcap_timing_valid = 1;
        } else {
            // Update last packet time
            g_last_packet_time = pkthdr->ts;
        }
    }
}

LmtData* parse_lmt(const u_char* data, int len) {
    
    if (!data) {
        printf("ERROR: NULL data pointer\n");
        return NULL;
    }
    
    if (len < 8) {
        printf("ERROR: LMT data too short (%d bytes)\n", len);
        return NULL;
    }
    
    // Validate the entire buffer is readable
    for (int test_pos = 0; test_pos < len; test_pos += 1024) {
        volatile uint8_t test_byte = data[test_pos];  // Force read
        (void)test_byte;  // Avoid unused variable warning
    }
    // Test the last byte
    volatile uint8_t last_byte = data[len-1];
    (void)last_byte;
    
    LmtData* lmt = calloc(1, sizeof(LmtData));
    if (!lmt) {
        printf("ERROR: Failed to allocate LmtData\n");
        return NULL;
    }
    
    // Start parsing LMT data at byte 5 (after 5-byte header)
    int pos = 5;
    if (pos >= len) {
        printf("ERROR: Cannot read service count byte at position %d (len=%d)\n", pos, len);
        free(lmt);
        return NULL;
    }
    
    // Parse number of services (6 bits) + placeholder (2 bits)
    uint8_t svc_byte = data[pos++];
    uint8_t num_svc_minus1 = (svc_byte >> 2) & 0x3F;
    
    lmt->num_services = 0;
    LmtService* service_tail = NULL;
    
    // Parse each service (which corresponds to a PLP)
    for (int svc_idx = 0; svc_idx <= num_svc_minus1; svc_idx++) {
        
        if (pos >= len - 2) {
            break;
        }
        
        // Parse PLP ID (6 bits) + placeholder (2 bits)
        uint8_t plp_byte = data[pos++];
        uint8_t plp_id = (plp_byte >> 2) & 0x3F;
        
        if (pos >= len) {
            break;
        }
        
        // Parse number of multicast entries for this PLP
        uint8_t num_multicasts = data[pos++];
        
        // Sanity check on multicast count
        if (num_multicasts > 10) {  // Reasonable upper limit
            printf("ERROR: Suspicious multicast count %d for PLP %d\n", num_multicasts, plp_id);
            break;
        }
        
        // Check if we have enough data for all multicasts
        size_t needed_bytes = num_multicasts * 13;  // 13 bytes per multicast minimum
        if (pos + needed_bytes > len) {
            printf("ERROR: Not enough data for %d multicasts (need %zu bytes, have %d)\n", 
                   num_multicasts, needed_bytes, len - pos);
            break;
        }
        
        // Create service entry for this PLP
        LmtService* service = calloc(1, sizeof(LmtService));
        if (!service) {
            printf("ERROR: Failed to allocate service for PLP %d\n", plp_id);
            continue;
        }
        
        service->service_id = lmt->num_services + 1;
        service->service_category = 1;
        service->plp_id = plp_id;
        snprintf(service->service_name, sizeof(service->service_name), "PLP_%d", plp_id);
        service->multicasts = NULL;  // Explicitly initialize
        service->next = NULL;        // Explicitly initialize
        
        LmtMulticast* current_service_multicast_tail = NULL;
        
        // Parse each multicast entry for this PLP
        for (int mc_idx = 0; mc_idx < num_multicasts; mc_idx++) {
            
            if (pos + 13 > len) {  // Need exactly 13 bytes
                printf("ERROR: Not enough data for multicast %d in PLP %d (need 13 bytes, have %d)\n", 
                       mc_idx, plp_id, len - pos);
                break;
            }
            
            // Create multicast entry
            LmtMulticast* multicast = calloc(1, sizeof(LmtMulticast));
            if (!multicast) {
                printf("ERROR: Failed to allocate multicast %d for PLP %d\n", mc_idx, plp_id);
                continue;
            }
            
            memset(multicast, 0, sizeof(LmtMulticast));  // Ensure everything is zeroed
            
            // Explicitly initialize all fields
            multicast->next = NULL;
            multicast->dest_ip_str[0] = '\0';
            multicast->dest_port_str[0] = '\0';
            
            // Parse multicast entry (13 bytes)
            multicast->src_ip = ntohl(*(uint32_t*)(data + pos));
            pos += 4;
            multicast->dest_ip = ntohl(*(uint32_t*)(data + pos));
            pos += 4;
            multicast->src_port = ntohs(*(uint16_t*)(data + pos));
            pos += 2;
            multicast->dest_port = ntohs(*(uint16_t*)(data + pos));
            pos += 2;
            
            // Parse flags
            uint8_t flags = data[pos++];
            multicast->sid_bit = (flags >> 7) & 0x1;
            multicast->compression_bit = (flags >> 6) & 0x1;
            
            // Convert to string format with bounds checking
            int ip_result = snprintf(multicast->dest_ip_str, sizeof(multicast->dest_ip_str), 
                    "%d.%d.%d.%d",
                    (multicast->dest_ip >> 24) & 0xff,
                    (multicast->dest_ip >> 16) & 0xff,
                    (multicast->dest_ip >> 8) & 0xff,
                    multicast->dest_ip & 0xff);
            
            int port_result = snprintf(multicast->dest_port_str, sizeof(multicast->dest_port_str), 
                    "%u", multicast->dest_port);
            
            if (ip_result <= 0 || port_result <= 0) {
                printf("ERROR: Failed to format IP/port strings for PLP %d multicast %d\n", plp_id, mc_idx);
                free(multicast);
                continue;
            }
            
            // Handle extra bytes if needed
            int extra_bytes = 0;
            if (multicast->sid_bit && multicast->compression_bit) extra_bytes = 2;
            else if (multicast->sid_bit || multicast->compression_bit) extra_bytes = 1;

            if (extra_bytes > 0) {
                if (pos + extra_bytes > len) {
                    printf("ERROR: Not enough data for extra bytes (%d needed)\n", extra_bytes);
                    free(multicast);
                    break;
                }
                
                // Actually READ the extra bytes instead of just skipping
                if (extra_bytes == 1) {
                    //uint8_t extra_byte = data[pos];
                    pos += 1;
                } else if (extra_bytes == 2) {
                    //uint16_t extra_word = ntohs(*(uint16_t*)(data + pos));
                    pos += 2;
                }
            }
                    
            // Before adding to linked list, validate the structure:
            if (multicast->dest_ip_str[0] == '\0' || multicast->dest_port_str[0] == '\0') {
                printf("ERROR: Invalid multicast entry for PLP %d, skipping\n", plp_id);
                free(multicast);
                continue;
            }

            // Double-check the next pointer is still NULL
            if (multicast->next != NULL) {
                printf("ERROR: multicast->next was corrupted during parsing!\n");
                multicast->next = NULL;
            }
            
            // Add to multicast list for this service
            if (service->multicasts == NULL) {
                service->multicasts = multicast;
                current_service_multicast_tail = multicast;
            } else {
                if (!current_service_multicast_tail) {
                    printf("ERROR: multicast_tail is NULL but service->multicasts is not\n");
                    free(multicast);
                    break;
                }
                current_service_multicast_tail->next = multicast;
                current_service_multicast_tail = multicast;
            }
        }

        
        // Add service to LMT
        if (lmt->services == NULL) {
            lmt->services = service;
            service_tail = service;
        } else {
            if (!service_tail) {
                printf("ERROR: service_tail is NULL but lmt->services is not\n");
                free(service);  // This will leak multicasts, but prevents crash
                break;
            }
            service_tail->next = service;
            service_tail = service;
        }
        lmt->num_services++;
    }
    
    return lmt;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    static int alp_packet_count = 0;
    alp_packet_count++;
    
    g_packet_count++;
    update_packet_timing(pkthdr);
    
    if (g_link_type == DLT_ATSC_ALP) {
        const u_char* ip_payload;
        const u_char* signaling_payload;
        int ip_len, signaling_len;
        
        int result = parse_alp_packet(packet, pkthdr->caplen, 
                                    &ip_payload, &ip_len, 
                                    &signaling_payload, &signaling_len);
        
        if (result == 0 && ip_payload) {
            // Process IP packet using existing logic
            const struct ip *ip_header = (struct ip*)ip_payload;
            if (!ip_header) {
                return;
            }
            
            int ip_header_len = ip_header->ip_hl * 4;

            if (ip_header->ip_p != IPPROTO_UDP) {
                return;
            }

            const struct udphdr *udp_header = (struct udphdr*)((u_char*)ip_header + ip_header_len);
            if (!udp_header) {
                return;
            }
            
            const u_char *udp_payload = (u_char*)udp_header + sizeof(struct udphdr);
            int udp_payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
            if (udp_payload_len <= 0) return;

            char dest_ip_str[40];
            char dest_port_str[16];
            inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip_str, sizeof(dest_ip_str));
            snprintf(dest_port_str, sizeof(dest_port_str), "%u", ntohs(udp_header->uh_dport));
            
            //printf("DEBUG: ALP UDP Packet %d - %s:%s, len=%d\n", g_packet_count, dest_ip_str, dest_port_str, udp_payload_len);
            
            // Check if this is a BPS packet
            if (is_bps_service(dest_ip_str, dest_port_str)) {
                const u_char *udp_payload = (u_char*)udp_header + sizeof(struct udphdr);
                int udp_payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
                
                if (udp_payload_len > 0 && !g_bps_data) {
                    g_bps_data = parse_bps_packet(udp_payload, udp_payload_len);
                }
                
                record_data_usage(dest_ip_str, dest_port_str, 0, pkthdr->caplen, 
                                "Broadcast Positioning System (BPS)");
                return;  // Don't process as regular ROUTE/MMT
            }
            
            // Check if this is LLS first
            int is_lls = (ntohs(udp_header->uh_dport) == 4937 && 
                        ip_header->ip_dst.s_addr == inet_addr("224.0.23.60"));
            
            if (is_lls) {
                process_lls_payload(udp_payload, udp_payload_len);
                record_data_usage(dest_ip_str, dest_port_str, 0, udp_payload_len, 
                                "ATSC 3.0 LLS (Low Level Signaling)");
                return;
            }
            
            //printf("DEBUG: Looking up service destination, count=%d\n", g_service_dest_count);
            
            // Find matching service destination from SLT
            ServiceDestination* dest_info = NULL;
            for(int i = 0; i < g_service_dest_count; i++) {
                if(ip_header->ip_dst.s_addr == g_service_dests[i].ip_addr.s_addr &&
                ntohs(udp_header->uh_dport) == g_service_dests[i].port) {
                    dest_info = &g_service_dests[i];
                    //printf("DEBUG: Found service destination at index %d\n", i);
                    break;
                }
            }
            
            if (dest_info) {
                //printf("DEBUG: Using service protocol=%s\n", dest_info->protocol);
                
                // Use SLT configuration to determine protocol
                if (strcmp(dest_info->protocol, "1") == 0) {
                    // ROUTE protocol
                    uint32_t tsi = 0;
                    if (udp_payload_len >= 12) {
                        tsi = ntohl(*(uint32_t*)(udp_payload + 8));
                    }
                    
                    if (g_packet_count % 50 == 0) {
                        //printf("DEBUG ROUTE HEADER: Packet %d, TSI=%u from offset 8\n", g_packet_count, tsi);
                    }
                    
                    const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                            tsi, "ROUTE", 0);
                    record_data_usage(dest_ip_str, dest_port_str, tsi, udp_payload_len, description);
                    process_route_payload(udp_payload, udp_payload_len, dest_info->destinationIpStr, dest_info->destinationPortStr);
                } else if (strcmp(dest_info->protocol, "2") == 0) {
                    // MMT protocol  
                    uint16_t packet_id = 0;
                    if (udp_payload_len >= 12) {
                        packet_id = ntohs(*(uint16_t*)(udp_payload + 10));
                    }
                    
                    const char* description = get_stream_description(dest_ip_str, dest_port_str, packet_id);
                    if (!description) {
                        //printf("DEBUG: NULL description from get_stream_description\n");
                        description = "MMT Stream";
                    }
                    
                    record_data_usage(dest_ip_str, dest_port_str, packet_id, udp_payload_len, description);
                    process_enhanced_mmt_payload(udp_payload, udp_payload_len, dest_info);
                }
            } else {
                //printf("DEBUG: No service destination found, using fallback\n");
                uint32_t tsi_or_packet_id = 0;
                const char* description = "Unknown UDP Stream";
                record_data_usage(dest_ip_str, dest_port_str, tsi_or_packet_id, udp_payload_len, description);
            }
            
        } else if (result == 1 && signaling_payload) {
            // Process ALP signaling packet
            //printf("Processing ALP signaling packet (%d bytes)\n", signaling_len);
            
            LmtData* lmt_data = parse_lmt(signaling_payload, signaling_len);
            if (lmt_data) {
                // Store LMT in global tables
                char lmt_content_id[256];
                snprintf(lmt_content_id, sizeof(lmt_content_id), 
                        "LMT_Version_%d_Services_%d", lmt_data->lmt_version, lmt_data->num_services);
                
                store_unique_table(lmt_content_id, strlen(lmt_content_id), 
                                TABLE_TYPE_LMT, lmt_data, "", "");
            }
            
        } /*else {
            printf("DEBUG: Could not parse ALP packet %d (result=%d)\n", g_packet_count, result);
        }*/
        
        return;
    }
    
    const struct ip *ip_header;
    const struct udphdr *udp_header;
    const u_char *payload;
    int ip_header_len;
    int payload_len;

    int offset = 0;
    const u_char* ip_packet_start = packet;  
    
    // Handle different link layer types
    if (g_link_type == DLT_EN10MB) {
        offset = sizeof(struct ether_header);
        ip_packet_start = packet + offset;
    }
    // For DLT_IPV4, no offset needed

    ip_header = (struct ip*)ip_packet_start;
    if (!ip_header) {
        return;
    }
    
    ip_header_len = ip_header->ip_hl * 4;

    if (ip_header->ip_p != IPPROTO_UDP) {
        return;
    }

    udp_header = (struct udphdr*)((u_char*)ip_header + ip_header_len);
    if (!udp_header) {
        return;
    }
    
    payload = (u_char*)udp_header + sizeof(struct udphdr);
    payload_len = ntohs(udp_header->uh_ulen) - sizeof(struct udphdr);
    if (payload_len <= 0) return;

    char dest_ip_str[40];
    char dest_port_str[16];
    inet_ntop(AF_INET, &ip_header->ip_dst, dest_ip_str, sizeof(dest_ip_str));
    snprintf(dest_port_str, sizeof(dest_port_str), "%u", ntohs(udp_header->uh_dport));
    
    //printf("DEBUG: Packet %d - %s:%s, len=%d\n", g_packet_count, dest_ip_str, dest_port_str, payload_len);
    
    // Check if this is LLS first
    int is_lls = (ntohs(udp_header->uh_dport) == 4937 && 
                  ip_header->ip_dst.s_addr == inet_addr("224.0.23.60"));
    
    if (is_lls) {
        process_lls_payload(payload, payload_len);
        record_data_usage(dest_ip_str, dest_port_str, 0, payload_len, 
                         "ATSC 3.0 LLS (Low Level Signaling)");
        return;
    }
    
    //printf("DEBUG: Looking up service destination, count=%d\n", g_service_dest_count);
    
    // Find matching service destination from SLT
    ServiceDestination* dest_info = NULL;
    for(int i = 0; i < g_service_dest_count; i++) {
        if(ip_header->ip_dst.s_addr == g_service_dests[i].ip_addr.s_addr &&
           ntohs(udp_header->uh_dport) == g_service_dests[i].port) {
            dest_info = &g_service_dests[i];
            //printf("DEBUG: Found service destination at index %d\n", i);
            break;
        }
    }
    
    if (dest_info) {
        //printf("DEBUG: Using service protocol=%s\n", dest_info->protocol);
        
        // Use SLT configuration to determine protocol
        if (strcmp(dest_info->protocol, "1") == 0) {
            // ROUTE protocol
            uint32_t tsi = 0;
            if (payload_len >= 12) {  // Need at least 12 bytes now
                tsi = ntohl(*(uint32_t*)(payload + 8));  // CHANGED: offset 8 instead of 4
            }
            
            if (g_packet_count % 50 == 0) {
                //printf("DEBUG ROUTE HEADER: Packet %d, TSI=%u from offset 8\n", g_packet_count, tsi);
            }
            
            const char* description = get_enhanced_stream_description(dest_ip_str, dest_port_str, 
                                                                    tsi, "ROUTE", 0);
            record_data_usage(dest_ip_str, dest_port_str, tsi, payload_len, description);
            process_route_payload(payload, payload_len, dest_info->destinationIpStr, dest_info->destinationPortStr);
        } else if (strcmp(dest_info->protocol, "2") == 0) {
            // MMT protocol  
            uint16_t packet_id = 0;
            if (payload_len >= 12) {
                packet_id = ntohs(*(uint16_t*)(payload + 10));
            }
            //printf("DEBUG: MMT PID=%u\n", packet_id);
            
            const char* description = get_stream_description(dest_ip_str, dest_port_str, packet_id);
            if (!description) {
                //printf("DEBUG: NULL description from get_stream_description\n");
                description = "MMT Stream";
            }
            
            record_data_usage(dest_ip_str, dest_port_str, packet_id, payload_len, description);
            process_enhanced_mmt_payload(payload, payload_len, dest_info);
        }
    } else {
        //printf("DEBUG: No service destination found, using fallback\n");
        // Use the original fallback logic temporarily
        uint32_t tsi_or_packet_id = 0;
        
        // Skip the protocol detection for now to avoid crashes
        const char* description = "Unknown UDP Stream";
        record_data_usage(dest_ip_str, dest_port_str, tsi_or_packet_id, payload_len, description);
    }
    
    //printf("DEBUG: Packet %d complete\n", g_packet_count);
}

const char* get_enhanced_stream_description(const char* dest_ip, const char* dest_port, 
                                          uint32_t tsi_or_packet_id, const char* stream_type, int is_lls) {
    static char desc_buffer[256];
    
    if (is_lls) {
        return "ATSC 3.0 LLS (Low Level Signaling)";
    }
    
    if (is_bps_service(dest_ip, dest_port)) {
        return "BPS (Broadcast Positioning System)";
    }
    
    // Get service name from SLT
    const char* service_name = get_service_name_for_destination(dest_ip, dest_port);
    
    // Get detailed media type from signaling tables
    const char* media_type = "Media";
    const char* detailed_info = "";
    
    if (strcmp(stream_type, "ROUTE") == 0) {
        if (tsi_or_packet_id == 0) {
            media_type = "Signaling";
        } else {
            // Look up TSI in S-TSID for detailed info
            //printf("stsid being called  \n");
            media_type = get_media_type_from_stsid(dest_ip, dest_port, tsi_or_packet_id);
            /*for (int i = 0; i < g_lls_table_count; i++) {
                if (g_lls_tables[i].type == TABLE_TYPE_STSID &&
                    strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
                    strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
                    
                    StsidData* stsid_data = (StsidData*)g_lls_tables[i].parsed_data;
                    StsidLogicalStream* ls = stsid_data->head_ls;
                    
                    while (ls) {
                        if (atoi(ls->tsi) == tsi_or_packet_id) {
                            if (strstr(ls->contentType, "video") || strstr(ls->repId, "video")) {
                                media_type = "Video";
                                // Try to extract resolution/quality info from repId
                                if (strstr(ls->repId, "1080")) detailed_info = " (1080p)";
                                else if (strstr(ls->repId, "720")) detailed_info = " (720p)";
                                else if (strstr(ls->repId, "480")) detailed_info = " (480p)";
                            } else if (strstr(ls->contentType, "audio") || strstr(ls->repId, "audio")) {
                                media_type = "Audio";
                                if (strstr(ls->repId, "128k")) detailed_info = " (128k)";
                                else if (strstr(ls->repId, "256k")) detailed_info = " (256k)";
                            } else if (strstr(ls->contentType, "application") || strstr(ls->repId, "cc")) {
                                media_type = "Captions";
                            }
                            break;
                        }
                        ls = ls->next;
                    }
                }
            }*/
        }
    } else if (strcmp(stream_type, "MMT") == 0) {
        // Similar lookup for MMT using MP Table data
        media_type = get_media_type_from_mpt(dest_ip, dest_port, tsi_or_packet_id);
    }
    
    // Build comprehensive description
    if (service_name) {
        if (strcmp(stream_type, "ROUTE") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s - ROUTE %s%s (TSI %u)", 
                    service_name, media_type, detailed_info, tsi_or_packet_id);
        } else if (strcmp(stream_type, "MMT") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s - MMT %s%s (PID %u)", 
                    service_name, media_type, detailed_info, tsi_or_packet_id);
        } else {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s - %s %s%s", 
                    service_name, stream_type, media_type, detailed_info);
        }
    } else {
        if (strcmp(stream_type, "ROUTE") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "ROUTE %s%s (TSI %u)", 
                    media_type, detailed_info, tsi_or_packet_id);
        } else if (strcmp(stream_type, "MMT") == 0) {
            snprintf(desc_buffer, sizeof(desc_buffer), "MMT %s%s (PID %u)", 
                    media_type, detailed_info, tsi_or_packet_id);
        } else {
            snprintf(desc_buffer, sizeof(desc_buffer), "%s %s Stream%s", 
                    stream_type, media_type, detailed_info);
        }
    }
    
    return desc_buffer;
}

int is_likely_route_packet(const uint8_t* payload, int len) {
    if (len < 8) return 0;
    
    // Check for LCT header patterns
    // LCT version should be 1, and header should have reasonable length
    uint8_t version = (payload[0] >> 6) & 0x3;
    uint8_t hdr_len = payload[2]; // Header length in 32-bit words
    
    if (version == 1 && hdr_len >= 2 && hdr_len <= 16) {
        // Check if TSI field looks reasonable (usually 0-255 for signaling/media)
        uint32_t tsi = ntohl(*(uint32_t*)(payload + 4));
        if (tsi <= 1000) { // Reasonable TSI range
            return 1;
        }
    }
    
    return 0;
}

int is_likely_mmt_packet(const uint8_t* payload, int len) {
    if (len < 12) return 0;
    
    // Check for MMT packet header patterns
    uint8_t version = (payload[0] >> 6) & 0x3;
    uint16_t packet_id = ntohs(*(uint16_t*)(payload + 10));
    
    // MMT version should be 0, packet ID should be reasonable
    if (version == 0 && packet_id < 8192) {
        return 1;
    }
    
    return 0;
}

int is_likely_rtp_packet(const uint8_t* payload, int len) {
    if (len < 12) return 0;
    
    // Check for RTP header patterns
    uint8_t version = (payload[0] >> 6) & 0x3;
    uint8_t payload_type = payload[1] & 0x7F;
    
    // RTP version should be 2, payload type should be reasonable
    if (version == 2 && payload_type <= 127) {
        return 1;
    }
    
    return 0;
}

const char* infer_content_type_from_context(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type) {
    // Try to infer content type from port numbers and patterns
    int port = atoi(dest_port);
    
    // Common port patterns
    if (port == 5001 || port == 5002) {
        // Check IP pattern for multiple streams on same port (likely different content types)
        struct in_addr addr;
        inet_aton(dest_ip, &addr);
        uint32_t ip_int = ntohl(addr.s_addr);
        uint8_t last_octet = ip_int & 0xFF;
        
        // If we see multiple IPs on same port, try to differentiate
        if (port == 5001) {
            // Guess based on last octet or other patterns
            if (last_octet % 4 == 1) return "Video";
            if (last_octet % 4 == 2) return "Audio"; 
            if (last_octet % 4 == 3) return "Data";
            return "Video"; // Default guess for 5001
        }
    }
    
    // Port 5100 often used for signaling
    if (port == 5100) return "Signaling";
    
    // RTP payload type hints
    if (strcmp(stream_type, "RTP") == 0) {
        // Common RTP payload types
        if (id >= 96 && id <= 127) return "Video"; // Dynamic payload types often video
        if (id >= 0 && id <= 23) return "Audio";   // Static audio payload types
        return "Media";
    }
    
    // Default based on stream type
    if (strcmp(stream_type, "ROUTE") == 0 || strcmp(stream_type, "MMT") == 0) {
        if (id == 0) return "Signaling";
        return "Media";
    }
    
    return "Media";
}

const char* get_media_type_from_stsid(const char* dest_ip, const char* dest_port, uint32_t tsi) {
    //printf("ENTERED get_media_type_from_stsid with %s:%s TSI=%u\n", dest_ip, dest_port, tsi);
    //printf("DEBUG S-TSID LOOKUP: Searching for %s:%s TSI=%u\n", dest_ip, dest_port, tsi);
    
    // Search through S-TSID tables to find media type for this TSI
    //printf("DEBUG S-TSID: Starting loop through %d total tables\n", g_lls_table_count);
    for (int i = 0; i < g_lls_table_count; i++) {
        //printf("DEBUG S-TSID: Checking table %d, type=%d\n", i, g_lls_tables[i].type);
        if (g_lls_tables[i].type == TABLE_TYPE_STSID) {
            //printf("DEBUG S-TSID LOOKUP: Checking table %d: IP='%s' vs '%s', Port='%s' vs '%s'\n", 
            //       i, g_lls_tables[i].destinationIp, dest_ip, 
            //       g_lls_tables[i].destinationPort, dest_port);
            
            if (strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
                strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
                
                //printf("DEBUG S-TSID LOOKUP: Found matching S-TSID table for %s:%s\n", dest_ip, dest_port);
                
                StsidData* stsid_data = (StsidData*)g_lls_tables[i].parsed_data;
                StsidLogicalStream* ls = stsid_data->head_ls;
                
                while (ls) {
                    //printf("DEBUG S-TSID LOOKUP: Checking LS TSI=%s against target %u\n", ls->tsi, tsi);
                    if (atoi(ls->tsi) == tsi) {
                        //printf("DEBUG S-TSID LOOKUP: MATCH! TSI=%u contentType=%s repId=%s\n", 
                        //       tsi, ls->contentType, ls->repId);
                        
                        // Try to determine media type from content type
                        if (strstr(ls->contentType, "video") || strstr(ls->contentType, "Video")) {
                            return "Video";
                        } else if (strstr(ls->contentType, "audio") || strstr(ls->contentType, "Audio")) {
                            return "Audio";  
                        } else if (strstr(ls->contentType, "subtitles") || strstr(ls->contentType, "application") || strstr(ls->contentType, "text")) {
                            return "Captions";
                        } else if (strlen(ls->contentType) > 0) {
                            //printf("DEBUG S-TSID LOOKUP: Unknown contentType: %s\n", ls->contentType);
                            return ls->contentType;
                        }
                    }
                    ls = ls->next;
                }
                //printf("DEBUG S-TSID LOOKUP: No matching TSI found in S-TSID table\n");
            }
        }
    }
    
    //printf("DEBUG S-TSID LOOKUP: No S-TSID table found for %s:%s\n", dest_ip, dest_port);
    return "Media";
}

const char* get_media_type_from_mpt(const char* dest_ip, const char* dest_port, uint32_t packet_id) {
    // Search through MP Table data (both XML and binary)
    for (int i = 0; i < g_lls_table_count; i++) {
        if ((g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_XML ||
             g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_BINARY) &&
            strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
            
            if (g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_XML) {
                MpTableData* mpt_data = (MpTableData*)g_lls_tables[i].parsed_data;
                MptAsset* asset = mpt_data->head_asset;
                
                while (asset) {
                    if (atoi(asset->packetId) == packet_id) {
                        // Check asset type and ID for clues
                        if (strstr(asset->assetType, "video") || strstr(asset->assetId, "video") ||
                            strstr(asset->assetId, "Video") || strstr(asset->assetId, "hev") ||
                            strstr(asset->assetId, "hvc")) {
                            return "Video";
                        } else if (strstr(asset->assetType, "audio") || strstr(asset->assetId, "audio") ||
                                   strstr(asset->assetId, "Audio") || strstr(asset->assetId, "ac-4") ||
                                   strstr(asset->assetId, "mp4a")) {
                            return "Audio";
                        } else if (strstr(asset->assetType, "data") || strstr(asset->assetId, "Data") ||
                                   strstr(asset->assetId, "stpp") || strstr(asset->assetId, "cc")) {
                            return "Data/Captions";
                        }
                        return asset->assetType;
                    }
                    asset = asset->next;
                }
            } else if (g_lls_tables[i].type == TABLE_TYPE_MP_TABLE_BINARY) {
                // CHANGED: Use ProprietaryMptData instead of BinaryMptData
                ProprietaryMptData* mpt_data = (ProprietaryMptData*)g_lls_tables[i].parsed_data;
                ProprietaryMptAsset* asset = mpt_data->assets;
                
                while (asset) {
                    if (asset->packet_id == packet_id) {  // FIXED: packet_id not packetId
                        return asset->asset_type;  // FIXED: asset_type not assetType
                    }
                    asset = asset->next;
                }
            }
        }
    }
    
    // Fallback - guess based on packet ID patterns (common convention)
    if (packet_id == 0) return "Signaling";
    if (packet_id >= 256 && packet_id <= 511) return "Video";
    if (packet_id >= 512 && packet_id <= 767) return "Audio";
    if (packet_id >= 768) return "Data/Captions";
    
    return "Media";
}

const char* get_extended_stream_description(const char* dest_ip, const char* dest_port, uint32_t id, const char* stream_type) {
    static char ext_desc_buffer[256];
    
    // Check if this IP:port appears in any signaling table, even if not in main service list
    for (int i = 0; i < g_lls_table_count; i++) {
        if (strlen(g_lls_tables[i].destinationIp) > 0 &&
            strcmp(g_lls_tables[i].destinationIp, dest_ip) == 0 &&
            strcmp(g_lls_tables[i].destinationPort, dest_port) == 0) {
            
            // Found signaling for this IP:port - try to get service name
            const char* service_name = get_service_name_for_destination(dest_ip, dest_port);
            const char* media_type = "Media";
            
            if (strcmp(stream_type, "ROUTE") == 0) {
                media_type = get_media_type_from_stsid(dest_ip, dest_port, id);
            } else if (strcmp(stream_type, "MMT") == 0) {
                media_type = get_media_type_from_mpt(dest_ip, dest_port, id);
            }
            
            if (service_name) {
                snprintf(ext_desc_buffer, sizeof(ext_desc_buffer), "%s - %s %s", 
                        service_name, stream_type, media_type);
            } else {
                snprintf(ext_desc_buffer, sizeof(ext_desc_buffer), "%s %s Stream", stream_type, media_type);
            }
            return ext_desc_buffer;
        }
    }
    
    return NULL; // Not found
}

const char* get_service_name_for_destination(const char* dest_ip, const char* dest_port) {
    // Special case for LLS
    if (strcmp(dest_ip, "224.0.23.60") == 0 && strcmp(dest_port, "4937") == 0) {
        return "LLS Signaling";
    }
    
    // Special case for BPS
    if (is_bps_service(dest_ip, dest_port)) {
        return "BPS Packet(s)";
    }
    
    // Look through all SLT entries to find service name
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while (service) {
                if (strcmp(service->slsDestinationIpAddress, dest_ip) == 0 &&
                    strcmp(service->slsDestinationUdpPort, dest_port) == 0) {
                    return service->shortServiceName;
                }
                service = service->next;
            }
        }
    }
    return NULL;
}

/**
 * @brief Calculates the total length of an LCT header based on the HDR_LEN field.
 */
uint16_t get_route_header_length(const u_char* payload, int len) {
    // The LCT header requires at least 4 bytes to read HDR_LEN.
    if (len < 4) return 0;
    
    // Read the HDR_LEN field from the 3rd byte (index 2).
    // HDR_LEN is the total header length in 32-bit words.
    uint8_t hdr_len_words = payload[2];
    uint16_t total_header_len = hdr_len_words * 4;

    // Sanity check: The header length cannot be smaller than the minimum LCT header
    // that contains the length field itself, and it cannot exceed the total packet payload length.
    if (total_header_len < 4 || total_header_len > len) {
        return 0;
    }

    return total_header_len;
}

/**
 * @brief Calculates the offset to the ROUTE payload by accounting for both the
 * LCT header and the FEC Payload ID.
 * @return The calculated offset in bytes, or 0 on failure.
 */
uint16_t get_route_payload_offset(const u_char* payload, int len) {
    uint16_t lct_header_len = get_route_header_length(payload, len);
    if (lct_header_len == 0) return 0;

    // The FEC Payload ID is only present for ROUTE/ALC. For TSI=0 (signaling),
    // it consists of a 4-byte field.
    uint16_t fec_payload_id_len = 0;
    if (len >= 8) { // Need at least 8 bytes to read TSI
        uint32_t tsi = ntohl(*(uint32_t*)(payload + 4));
        if (tsi == 0) {
            fec_payload_id_len = 4;
        }
    }

    uint16_t total_offset = lct_header_len + fec_payload_id_len;
    
    // Final sanity check
    if (total_offset > len) {
        return 0;
    }

    return total_offset;
}

int is_esg_service(const char* destIp, const char* destPort) {
    //printf("DEBUG ESG CHECK: Checking if %s:%s is ESG service\n", destIp, destPort);
    for(int i = 0; i < g_service_dest_count; i++) {
        if(strcmp(g_service_dests[i].destinationIpStr, destIp) == 0 &&
           strcmp(g_service_dests[i].destinationPortStr, destPort) == 0) {
            //printf("DEBUG ESG CHECK: Found service, category=%s, isEsgService=%d\n", 
            //       g_service_dests[i].serviceCategory, g_service_dests[i].isEsgService);
            return g_service_dests[i].isEsgService;
        }
    }
    //printf("DEBUG ESG CHECK: Service not found in g_service_dests\n");
    return 0;
}

/**
 * @brief Enhanced function to detect truncated/corrupted duplicates
 */
int is_truncated_duplicate(const char* content1, const char* content2) {
    if (!content1 || !content2) return 0;
    
    size_t len1 = strlen(content1);
    size_t len2 = strlen(content2);
    
    // If lengths are identical, do exact comparison
    if (len1 == len2) {
        return strcmp(content1, content2) == 0;
    }
    
    // Must be substantial content to consider for duplicate detection
    if (len1 < 200 || len2 < 200) return 0;
    
    // Extract root element names for both documents
    char root1[64] = "";
    char root2[64] = "";
    
    // Find first root element in content1
    const char* start1 = strstr(content1, "<");
    if (start1) {
        start1 = strstr(start1, "<S-TSID") ? strstr(start1, "<S-TSID") : 
                 strstr(start1, "<MPD") ? strstr(start1, "<MPD") :
                 strstr(start1, "<FDT-Instance") ? strstr(start1, "<FDT-Instance") : NULL;
        if (start1) {
            const char* end1 = strchr(start1 + 1, ' ');
            if (!end1) end1 = strchr(start1 + 1, '>');
            if (end1) {
                int root_len = (end1 - start1 - 1) < 63 ? (end1 - start1 - 1) : 63;
                strncpy(root1, start1 + 1, root_len);
                root1[root_len] = '\0';
            }
        }
    }
    
    // Find first root element in content2
    const char* start2 = strstr(content2, "<");
    if (start2) {
        start2 = strstr(start2, "<S-TSID") ? strstr(start2, "<S-TSID") : 
                 strstr(start2, "<MPD") ? strstr(start2, "<MPD") :
                 strstr(start2, "<FDT-Instance") ? strstr(start2, "<FDT-Instance") : NULL;
        if (start2) {
            const char* end2 = strchr(start2 + 1, ' ');
            if (!end2) end2 = strchr(start2 + 1, '>');
            if (end2) {
                int root_len = (end2 - start2 - 1) < 63 ? (end2 - start2 - 1) : 63;
                strncpy(root2, start2 + 1, root_len);
                root2[root_len] = '\0';
            }
        }
    }
    
    // Only compare documents with the same root element
    if (strlen(root1) == 0 || strlen(root2) == 0 || strcmp(root1, root2) != 0) {
        return 0;
    }
    
    // Find the main content portion of each document (after XML declaration)
    const char* main1 = strstr(content1, root1);
    const char* main2 = strstr(content2, root2);
    
    if (!main1 || !main2) return 0;
    
    // Compare the beginnings - look for substantial overlap
    size_t compare_len = (len1 < len2) ? len1 / 2 : len2 / 2;  // Compare first half of shorter doc
    if (compare_len < 500) compare_len = 500;  // Minimum comparison length
    
    if (main1 - content1 + compare_len > len1) compare_len = len1 - (main1 - content1);
    if (main2 - content2 + compare_len > len2) compare_len = len2 - (main2 - content2);
    
    // Check if the main portions match for the comparison length
    if (memcmp(main1, main2, compare_len) == 0) {
        // They start the same - now check if one is truncated/corrupted
        
        // Look for proper closing tag in both
        char closing_tag[70];
        snprintf(closing_tag, sizeof(closing_tag), "</%s>", root1);
        
        const char* close1 = strstr(content1, closing_tag);
        const char* close2 = strstr(content2, closing_tag);
        
        // If one has proper closing and the other doesn't, it's likely a truncated duplicate
        if (close1 && !close2) {
            return 1;  // content1 is complete, content2 is truncated
        }
        if (!close1 && close2) {
            return 1;  // content2 is complete, content1 is truncated
        }
        
        // If both have closing tags, check if one is clearly shorter/incomplete
        if (close1 && close2) {
            size_t doc1_end = (close1 - content1) + strlen(closing_tag);
            size_t doc2_end = (close2 - content2) + strlen(closing_tag);
            
            // If there's significant length difference and substantial content match,
            // consider it a duplicate where one has extra content appended
            if (abs((int)(doc1_end - doc2_end)) > 100 && compare_len > 1000) {
                return 1;
            }
        }
        
        // Additional check: if one document has corrupted content after the main portion
        // (like XML declarations in the middle), it's likely corrupted
        const char* xml_decl_mid1 = strstr(main1 + 100, "<?xml");
        const char* xml_decl_mid2 = strstr(main2 + 100, "<?xml");
        
        if ((xml_decl_mid1 && !xml_decl_mid2) || (!xml_decl_mid1 && xml_decl_mid2)) {
            return 1;  // One has corrupted content
        }
    }
    
    return 0;
}

char* normalize_xml_declaration(const char* xml_content) {
    if (!xml_content) return NULL;
    
    // Skip XML declaration if present
    const char* content_start = xml_content;
    if (strncmp(xml_content, "<?xml", 5) == 0) {
        const char* decl_end = strstr(xml_content, "?>");
        if (decl_end) {
            content_start = decl_end + 2;
            // Skip any whitespace after declaration
            while (*content_start && isspace(*content_start)) {
                content_start++;
            }
        }
    }
    
    return strdup(content_start);
}

/**
 * @brief Normalizes XML content by removing/standardizing commonly changing values
 * @param xml_content Original XML content
 * @param normalized_buffer Output buffer for normalized content
 * @param buffer_size Size of output buffer
 * @return 0 on success, -1 on failure
 */
int normalize_xml_content(const char* xml_content, char* normalized_buffer, size_t buffer_size) {
    if (!xml_content || !normalized_buffer || buffer_size == 0) return -1;
    
    strncpy(normalized_buffer, xml_content, buffer_size - 1);
    normalized_buffer[buffer_size - 1] = '\0';
    
    // For metadataEnvelope: normalize version numbers to a placeholder
    if (strstr(normalized_buffer, "<metadataEnvelope")) {
        char* version_start = strstr(normalized_buffer, "version=\"");
        while (version_start) {
            version_start += 9; // Skip 'version="'
            char* version_end = strchr(version_start, '"');
            if (version_end) {
                // Replace version number with placeholder
                memmove(version_start + 9, version_end, strlen(version_end) + 1);
                memcpy(version_start, "XXXXXXXXX", 9); // Fixed length placeholder
            }
            version_start = strstr(version_end ? version_end : normalized_buffer, "version=\"");
        }
    }
    
    // For MPD: normalize publishTime and timeline t values
    if (strstr(normalized_buffer, "<MPD")) {
        
        // Normalize publishTime
        char* publish_start = strstr(normalized_buffer, "publishTime=\"");
        if (publish_start) {
            publish_start += 13; // Skip 'publishTime="'
            char* publish_end = strchr(publish_start, '"');
            if (publish_end && publish_end > publish_start) { // Make sure we found a different quote
                size_t time_len = publish_end - publish_start;
                
                // Replace each character with 'X'
                for (size_t i = 0; i < time_len; i++) {
                    publish_start[i] = 'X';
                }
                
            } 
        } 
        
        // Normalize SegmentTimeline t values - CONSISTENT WITH PUBLISHTIME
        // Normalize ALL t attributes anywhere in the document
        char* pos = normalized_buffer;
        while ((pos = strstr(pos, " t=\"")) != NULL) {
            pos += 4; // Skip ' t="'
            char* end_quote = strchr(pos, '"');
            if (end_quote) {
                while (pos < end_quote) {
                    *pos = 'X';
                    pos++;
                }
            } else {
                break;
            }
        }
        
    }
    
    return 0;
}

/**
 * @brief Checks if two XML documents are functionally equivalent (ignoring version/timestamp changes)
 * @param content1 First XML document
 * @param content2 Second XML document
 * @return 1 if functionally equivalent, 0 if different
 */
int is_functionally_equivalent(const char* content1, const char* content2) {
    if (!content1 || !content2) return 0;
    
    // Quick exact match check first
    if (strcmp(content1, content2) == 0) return 1;
    
    // Normalize XML declarations FIRST
    char* normalized1 = normalize_xml_declaration(content1);
    char* normalized2 = normalize_xml_declaration(content2);
    
    if (!normalized1 || !normalized2) {
        free(normalized1);
        free(normalized2);
        return 0;
    }
    
    // Check if they match after removing declarations
    int match = (strcmp(normalized1, normalized2) == 0);
    
    free(normalized1);
    free(normalized2);
    
    if (match) return 1;
    
    // Check if both are same document type
    char doc_type1[64] = "";
    char doc_type2[64] = "";
    
    // Extract root element names
    const char* start1 = strchr(content1, '<');
    const char* start2 = strchr(content2, '<');
    
    if (start1 && start2) {
        // Skip XML declaration if present
        if (strncmp(start1, "<?xml", 5) == 0) {
            start1 = strstr(start1, "<") + 1;
            start1 = strchr(start1, '<');
        }
        if (strncmp(start2, "<?xml", 5) == 0) {
            start2 = strstr(start2, "<") + 1;
            start2 = strchr(start2, '<');
        }
        
        if (start1 && start2) {
            const char* end1 = strpbrk(start1 + 1, " >");
            const char* end2 = strpbrk(start2 + 1, " >");
            
            if (end1 && end2) {
                size_t len1 = end1 - start1 - 1;
                size_t len2 = end2 - start2 - 1;
                
                if (len1 < sizeof(doc_type1) && len2 < sizeof(doc_type2)) {
                    strncpy(doc_type1, start1 + 1, len1);
                    doc_type1[len1] = '\0';
                    strncpy(doc_type2, start2 + 1, len2);
                    doc_type2[len2] = '\0';
                }
            }
        }
    }
    
    // Only compare documents of the same type
    if (strlen(doc_type1) == 0 || strlen(doc_type2) == 0 || strcmp(doc_type1, doc_type2) != 0) {
        return 0;
    }
    
    // Normalize both documents and compare (for timestamp/version differences)
    char normalized_content1[65536];
    char normalized_content2[65536];
    
    if (normalize_xml_content(content1, normalized_content1, sizeof(normalized_content1)) != 0 ||
        normalize_xml_content(content2, normalized_content2, sizeof(normalized_content2)) != 0) {
        return 0;
    }
    
    match = (strcmp(normalized_content1, normalized_content2) == 0);

    return match;
}

/**
 * @brief Enhanced duplicate removal that handles functional equivalence
 */
void remove_functionally_duplicate_tables() {
    int removed_count = 0;
    
    for (int i = 0; i < g_lls_table_count; i++) {
        if (!g_lls_tables[i].content_id) continue;
        
        for (int j = i + 1; j < g_lls_table_count; j++) {
            if (!g_lls_tables[j].content_id) continue;
            
            // Only check tables of same type and destination
            if (g_lls_tables[i].type != g_lls_tables[j].type) continue;
            if (strcmp(g_lls_tables[i].destinationIp, g_lls_tables[j].destinationIp) != 0) continue;
            if (strcmp(g_lls_tables[i].destinationPort, g_lls_tables[j].destinationPort) != 0) continue;
            
            size_t len_i = strlen(g_lls_tables[i].content_id);
            size_t len_j = strlen(g_lls_tables[j].content_id);
            
            // Check for exact duplicates
            if (len_i == len_j && strcmp(g_lls_tables[i].content_id, g_lls_tables[j].content_id) == 0) {
                free(g_lls_tables[j].content_id);
                free_parsed_data(&g_lls_tables[j]);
                g_lls_tables[j].content_id = NULL;
                removed_count++;
                continue;
            }
            
            // NEW: Check if one is a truncated/corrupted version of the other
            // If one is much shorter and is a prefix of the longer one, it's corrupted
            size_t min_len = (len_i < len_j) ? len_i : len_j;
            size_t max_len = (len_i > len_j) ? len_i : len_j;
            
            // If lengths differ by more than 20% and the shorter one matches the start of the longer
            if (max_len > min_len * 1.1) {
                int is_prefix = (memcmp(g_lls_tables[i].content_id, g_lls_tables[j].content_id, min_len) == 0);
                
                if (is_prefix) {
                    // Keep the longer (more complete) one
                    int remove_index = (len_i < len_j) ? i : j;
                    
                    
                    free(g_lls_tables[remove_index].content_id);
                    free_parsed_data(&g_lls_tables[remove_index]);
                    g_lls_tables[remove_index].content_id = NULL;
                    removed_count++;
                    
                    if (remove_index == i) {
                        break; // i was removed, move to next i
                    }
                    continue;
                }
            }
            
            if (is_functionally_equivalent(g_lls_tables[i].content_id, g_lls_tables[j].content_id)) {
                // Determine which one to keep (prefer more recent timestamp if available)
                int remove_index = i; // Default: keep the NEWER one (j), remove the older (i)
                
                // For MPD documents, keep the one with more recent publishTime
                if (g_lls_tables[i].type == TABLE_TYPE_MPD) {
                    char* pub1 = strstr(g_lls_tables[i].content_id, "publishTime=\"");
                    char* pub2 = strstr(g_lls_tables[j].content_id, "publishTime=\"");
                    
                    if (pub1 && pub2) {
                        // Simple string comparison works for ISO timestamps
                        if (strncmp(pub1 + 13, pub2 + 13, 19) > 0) {
                            // i is NEWER, keep i, remove j
                            remove_index = j;
                        }
                        // else: j is newer or equal, remove i (already set)
                    }
                }
                
                // For S-TSID documents, keep the one with higher efdtVersion
                if (g_lls_tables[i].type == TABLE_TYPE_STSID) {
                    char* ver1 = strstr(g_lls_tables[i].content_id, "afdt:efdtVersion=\"");
                    char* ver2 = strstr(g_lls_tables[j].content_id, "afdt:efdtVersion=\"");
                    
                    if (ver1 && ver2) {
                        int version1 = atoi(ver1 + 18);
                        int version2 = atoi(ver2 + 18);
                        
                        if (version1 > version2) {
                            remove_index = j;
                        }
                    }
                }
                
                // For metadataEnvelope, try to keep the one with higher version
                if (g_lls_tables[i].type == TABLE_TYPE_SERVICE_SIGNALING) {
                    char* ver1 = strstr(g_lls_tables[i].content_id, "version=\"");
                    char* ver2 = strstr(g_lls_tables[j].content_id, "version=\"");
                    
                    if (ver1 && ver2) {
                        int version1 = atoi(ver1 + 9);
                        int version2 = atoi(ver2 + 9);
                        
                        if (version1 > version2) {
                            // i has higher version, keep i
                            remove_index = j;
                        } else {
                            // j has higher version, keep j
                            remove_index = i;
                        }
                    }
                }
                
                // Free the duplicate entry
                free(g_lls_tables[remove_index].content_id);
                free_parsed_data(&g_lls_tables[remove_index]);
                g_lls_tables[remove_index].content_id = NULL;
                g_lls_tables[remove_index].parsed_data = NULL;
                
                // Shift remaining entries down
                for (int k = remove_index; k < g_lls_table_count - 1; k++) {
                    g_lls_tables[k] = g_lls_tables[k + 1];
                }
                g_lls_table_count--;
                removed_count++;
                
                // Adjust loop indices since we removed an entry
                if (remove_index <= i) i--;
                if (remove_index < j) j--;
                
                break; // Found duplicate, move to next i
            }
        }
    }
    
    // Compact the array by removing NULL entries
    int write_idx = 0;
    for (int read_idx = 0; read_idx < g_lls_table_count; read_idx++) {
        if (g_lls_tables[read_idx].content_id != NULL) {
            if (write_idx != read_idx) {
                g_lls_tables[write_idx] = g_lls_tables[read_idx];
            }
            write_idx++;
        }
    }
    g_lls_table_count = write_idx;
}

/**
 * @brief Processes ROUTE packets. Buffers fragments based on a unique key of
 * IP, Port, and TOI. This ensures streams don't get mixed.
 */
void process_route_payload(const u_char* payload, int len, const char* destIp, const char* destPort) {
    if (len < 16) return; 

    uint32_t tsi = ntohl(*(uint32_t*)(payload + 8));
    uint32_t toi = ntohl(*(uint32_t*)(payload + 12));

    const char* description = get_stream_description(destIp, destPort, tsi);
    record_data_usage(destIp, destPort, tsi, len, description);
    
    if (tsi != 0 && !is_esg_service(destIp, destPort)) {
        return;
    }

    int close_object_flag = (payload[1] & 0x01);
    int close_session_flag = (payload[1] & 0x02) >> 1;
    
    uint16_t header_len = payload[2] * 4;
    uint16_t payload_offset = get_route_payload_offset(payload, len);
    
    if (payload_offset == 0 || len <= payload_offset) {
        return;
    }

    // Extract byte offset from FEC Payload ID
    // For ESG and other data streams, FEC Payload ID is also present
    uint32_t byte_offset = 0;
    if (len > header_len + 4) {
        byte_offset = ntohl(*(uint32_t*)(payload + header_len));
        
    }

    // Reassembly logic - find or create buffer
    ReassemblyBuffer *current_buf = NULL;
    for (current_buf = g_reassembly_head; current_buf != NULL; current_buf = current_buf->next) {
        if (current_buf->toi == toi && 
            current_buf->tsi == tsi &&
            strcmp(current_buf->destinationIp, destIp) == 0 &&
            strcmp(current_buf->destinationPort, destPort) == 0) 
        {
            break;
        }
    }

    if (current_buf == NULL) {
        current_buf = calloc(1, sizeof(ReassemblyBuffer));
        if (!current_buf) return;
        current_buf->toi = toi;
        current_buf->tsi = tsi;
        current_buf->mmt_header_len = -1;
        strncpy(current_buf->destinationIp, destIp, sizeof(current_buf->destinationIp) - 1);
        current_buf->destinationIp[sizeof(current_buf->destinationIp) - 1] = '\0';
        strncpy(current_buf->destinationPort, destPort, sizeof(current_buf->destinationPort) - 1);
        current_buf->destinationPort[sizeof(current_buf->destinationPort) - 1] = '\0';
        current_buf->next = g_reassembly_head;
        g_reassembly_head = current_buf;
        
    }

    const u_char* data_to_copy = payload + payload_offset;
    int len_to_copy = len - payload_offset;
    
    // Calculate required buffer size
    size_t required_size = byte_offset + len_to_copy;
    
    // Resize buffer if needed
    if (required_size > current_buf->size) {
        uint8_t* new_buffer = realloc(current_buf->buffer, required_size);
        if (!new_buffer) {
            fprintf(stderr, "Failed to realloc reassembly buffer!\n");
            return;
        }
        
        // Zero-fill any gaps
        if (byte_offset > current_buf->size) {
            memset(new_buffer + current_buf->size, 0, byte_offset - current_buf->size);
        }
        
        current_buf->buffer = new_buffer;
        current_buf->size = required_size;
    }
    
    // Write data at the specified byte offset
    memcpy(current_buf->buffer + byte_offset, data_to_copy, len_to_copy);
    

    if (close_object_flag || close_session_flag) {
        
        // NEW: Debug the reassembled buffer
        if (is_esg_service(destIp, destPort)) {
            
            // Check for GZIP signature
            if (current_buf->size >= 2) {
                if (current_buf->buffer[0] == 0x1f && current_buf->buffer[1] == 0x8b) {
                } else {
                    for (size_t i = 0; i < 100 && i < current_buf->size - 1; i++) {
                        if (current_buf->buffer[i] == 0x1f && current_buf->buffer[i+1] == 0x8b) {
                            
                            // Create new buffer starting from GZIP header
                            size_t new_size = current_buf->size - i;
                            uint8_t* new_buffer = malloc(new_size);
                            if (new_buffer) {
                                memcpy(new_buffer, current_buf->buffer + i, new_size);
                                free(current_buf->buffer);
                                current_buf->buffer = new_buffer;
                                current_buf->size = new_size;
                            }
                            break;
                        }
                    }
                    
                }
            }
        }
        
        if (current_buf->size < 10) {
            printf("WARN: Buffer too small (%zu bytes), discarding\n", current_buf->size);
        } else {
            process_and_store_route_object(current_buf->toi, current_buf->buffer, current_buf->size, 
                                        current_buf->destinationIp, current_buf->destinationPort);
        }
        
        // Remove from linked list
        if (g_reassembly_head == current_buf) {
            g_reassembly_head = current_buf->next;
        } else {
            ReassemblyBuffer* temp = g_reassembly_head;
            while(temp && temp->next != current_buf) {
                temp = temp->next;
            }
            if (temp) {
                temp->next = current_buf->next;
            }
        }
        
        free(current_buf->buffer);
        free(current_buf);
    }
}

/**
 * @brief Enhanced GZIP completion check with better debugging
 */
int is_gzip_complete(const uint8_t* buffer, size_t size) {
    if (size < 10) {
        return 0;
    }
    
    // Find GZIP header within the buffer (it might not be at offset 0)
    const uint8_t gzip_magic[] = {0x1f, 0x8b};
    const uint8_t* gzip_start = NULL;
    
    for (size_t i = 0; i <= size - 10; i++) {
        if (memcmp(buffer + i, gzip_magic, 2) == 0) {
            gzip_start = buffer + i;
            break;
        }
    }
    
    if (!gzip_start) {
        return 0;
    }
    
    size_t gzip_size = size - (gzip_start - buffer);
    
    // Try to decompress to check completeness
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = gzip_size;
    strm.next_in = (Bytef *)gzip_start;
    
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        return 0;
    }
    
    uint8_t temp_buf[4096];
    strm.avail_out = sizeof(temp_buf);
    strm.next_out = temp_buf;
    
    int ret = inflate(&strm, Z_SYNC_FLUSH);
    size_t bytes_produced = sizeof(temp_buf) - strm.avail_out;
    size_t bytes_consumed = gzip_size - strm.avail_in;
    
    int complete = 0;
    if (ret == Z_STREAM_END) {
        complete = 1;
    } else if (ret == Z_OK && bytes_produced > 0) {
        // Partial success - check if we're close to complete
        if (bytes_consumed == gzip_size && gzip_size > 200) {
            complete = 1;  // Consumed all input and produced output
        }
    }
    
    inflateEnd(&strm);
    
    // Fallback: if we have a lot of data and it starts with valid GZIP, assume complete
    if (!complete && gzip_size > 500) {
        complete = 1;
    }
    
    return complete;
}

/**
 * @brief Helper function to check if an XML document is complete
 */
int is_xml_complete(const char* buffer, size_t size) {
    // Simple check: look for common closing tags
    const char* closing_tags[] = {
        "</MP_Table>", "</BundleDescriptionMMT>", "</DWD>",
        "</metadataEnvelope>", "</FDT-Instance>", NULL
    };
    
    for (int i = 0; closing_tags[i] != NULL; i++) {
        if (memmem(buffer, size, closing_tags[i], strlen(closing_tags[i]))) {
            return 1;
        }
    }
    
    // Fallback: count opening and closing angle brackets
    int open_count = 0, close_count = 0;
    int in_tag = 0;
    for (size_t i = 0; i < size; i++) {
        if (buffer[i] == '<' && i + 1 < size && buffer[i+1] != '/') {
            open_count++;
            in_tag = 1;
        } else if (buffer[i] == '<' && i + 1 < size && buffer[i+1] == '/') {
            close_count++;
            in_tag = 1;
        } else if (buffer[i] == '>' && in_tag) {
            in_tag = 0;
        }
    }
    
    // If we have balanced tags and reasonable data, consider it complete
    return (open_count > 0 && open_count == close_count);
}



/**
 * @brief Simplified binary MP table parser with two-pass approach
 */
BinaryMptData* parse_binary_mp_table_multiformat(const uint8_t* buffer, size_t size) {
    if (size < 20) return NULL;
    
    BinaryMptData* mpt_data = calloc(1, sizeof(BinaryMptData));
    if (!mpt_data) return NULL;

    BinaryMptAsset* current_asset_tail = NULL;
    int assets_found = 0;
    
    // SIMPLIFIED approach: scan for all FE patterns first, then process each one
    typedef struct {
        const uint8_t* pos;
        size_t offset;
    } FePattern;
    
    FePattern fe_patterns[10];  // Up to 10 FE patterns
    int fe_count = 0;
    
    // First pass: find all FE 01 patterns
    for (size_t i = 0; i < size - 2 && fe_count < 10; i++) {
        if (buffer[i] == 0xFE && buffer[i+1] == 0x01) {
            fe_patterns[fe_count].pos = buffer + i;
            fe_patterns[fe_count].offset = i;
            fe_count++;
        }
    }
    
    // Second pass: process each FE pattern
    for (int i = 0; i < fe_count; i++) {
        const uint8_t* pos = fe_patterns[i].pos;
        
        if (pos + 20 >= buffer + size) {
            continue;
        }
        
        // Extract packet ID
        uint16_t packet_id = 0;
        if (pos[2] == 0x00 && pos[3] != 0x00) {
            packet_id = (pos[3] << 8) | pos[4];
        } else if (pos[2] == 0x00 && pos[3] == 0x00) {
            packet_id = pos[4] | (pos[5] << 8);
        }
        
        if (packet_id == 0 || packet_id >= 8192) {
            continue;
        }
        
        // Find the name by looking for next FE pattern or end of buffer
        const uint8_t* name_start = pos + 16;
        const uint8_t* name_end = buffer + size;  // Default to end of buffer
        
        if (i + 1 < fe_count) {
            name_end = fe_patterns[i + 1].pos;  // Next FE pattern
        }
        
        size_t name_len = name_end - name_start;
        
        // For the last pattern, the name might be very short or missing
        if (name_len == 0 && i == fe_count - 1) {
            
            // Create a generic asset for the last pattern
            BinaryMptAsset* asset = calloc(1, sizeof(BinaryMptAsset));
            if (asset) {
                snprintf(asset->assetId, sizeof(asset->assetId), "Asset_%u", packet_id);
                strcpy(asset->assetType, "unknown");
                asset->packetId = packet_id;
                
                // Add to linked list
                if (mpt_data->head_asset == NULL) {
                    mpt_data->head_asset = asset;
                    current_asset_tail = asset;
                } else {
                    current_asset_tail->next = asset;
                    current_asset_tail = asset;
                }
                
                assets_found++;
            }
            continue;
        }
        
        if (name_len > 0 && name_len < 50) {
            // Validate name contains printable characters
            int valid = 1;
            for (size_t j = 0; j < name_len; j++) {
                if (!isprint(name_start[j]) && name_start[j] != '-' && name_start[j] != '_') {
                    valid = 0;
                    break;
                }
            }
            
            if (valid) {
                
                // Create asset
                BinaryMptAsset* asset = calloc(1, sizeof(BinaryMptAsset));
                if (asset) {
                    memcpy(asset->assetId, name_start, name_len);
                    asset->assetId[name_len] = '\0';
                    asset->packetId = packet_id;
                    
                    // Determine type from asset name
                    if (strstr(asset->assetId, "video") || strstr(asset->assetId, "Video") || 
                        strstr(asset->assetId, "hev1") || strstr(asset->assetId, "hvc1")) {
                        strcpy(asset->assetType, "video");
                    } else if (strstr(asset->assetId, "audio") || strstr(asset->assetId, "Audio") || 
                               strstr(asset->assetId, "ac-4") || strstr(asset->assetId, "mp4a")) {
                        strcpy(asset->assetType, "audio");
                    } else if (strstr(asset->assetId, "cc") || strstr(asset->assetId, "stpp") || 
                               strstr(asset->assetId, "Data") || strstr(asset->assetId, "imsc")) {
                        strcpy(asset->assetType, "caption");
                    } else {
                        strcpy(asset->assetType, "unknown");
                    }
                    
                    // Add to linked list
                    if (mpt_data->head_asset == NULL) {
                        mpt_data->head_asset = asset;
                        current_asset_tail = asset;
                    } else {
                        current_asset_tail->next = asset;
                        current_asset_tail = asset;
                    }
                    
                    assets_found++;
                }
            }
        }
    }
    
    if (assets_found == 0) {
        free(mpt_data);
        return NULL;
    }
    
    return mpt_data;
}

// Enhanced completion detection for MMT signaling
int is_mmt_signaling_complete(const uint8_t* buffer, size_t size) {
    if (size < 10) return 0;
    
    // Check for GZIP header
    const uint8_t gzip_magic[] = {0x1f, 0x8b};
    if (size > 2 && memcmp(buffer, gzip_magic, 2) == 0) {
        return is_gzip_complete(buffer, size);
    }
    
    // Check for uncompressed binary MP table
    // Look for FE 01 00 pattern (various formats)
    for (size_t i = 0; i < size - 10; i++) {
        if (buffer[i] == 0xFE && buffer[i+1] == 0x01) {
            // Found potential MP table start - assume complete if we have reasonable size
            if (size > 100) return 1;
        }
    }
    
    // Check for XML patterns
    if (memmem(buffer, size, "<?xml", 5)) {
        return is_xml_complete((char*)buffer, size);
    }
    
    // For small buffers, require more data
    if (size < 50) return 0;
    
    // Default: assume complete if we have a reasonable amount of data
    return (size > 200);
}

/**
 * @brief Fixed MMT signaling processor with deduplication
 */
void process_mmt_signaling_payload(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    #if DEBUG_MMT
    char filename[256];
    snprintf(filename, sizeof(filename), "mmt_signaling_object_%d.bin", g_dump_count++);
    FILE* f_dump = fopen(filename, "wb");
    if (f_dump) {
        fwrite(buffer, 1, size, f_dump);
        fclose(f_dump);
    }
    #endif

    const uint8_t* payload_to_process = buffer;
    size_t size_to_process = size;
    char* decompressed_buffer = NULL;

    // Check for GZIP compression
    const uint8_t gzip_magic[] = {0x1f, 0x8b}; 
    if (size > 2 && memcmp(buffer, gzip_magic, 2) == 0) {
        int decompressed_size = 0;
        int consumed_size = 0;
        decompressed_buffer = decompress_gzip(buffer, size, &decompressed_size, &consumed_size);
        if(decompressed_buffer) {
            payload_to_process = (uint8_t*)decompressed_buffer;
            size_to_process = decompressed_size;
            
        } 
    }

    // Check if the payload is XML
    const char* xml_marker = "<?xml";
    const uint8_t* xml_start = NULL;
    
    // Search for XML marker (might not be at the beginning)
    for (int offset = 0; offset < size_to_process && offset < 100; offset++) {
        if (size_to_process - offset > 5 && 
            memcmp(payload_to_process + offset, xml_marker, 5) == 0) {
            xml_start = payload_to_process + offset;
            break;
        }
    }

    if (xml_start) {
        size_t xml_len = size_to_process - (xml_start - payload_to_process);
        
        
        char source_id[512];
        snprintf(source_id, sizeof(source_id), "MMT Signaling (XML) on %s:%s", destIp, destPort);

        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        if (parse_xml((const char*)xml_start, xml_len, &type, &parsed_data, source_id) == 0) {
            if (parsed_data) {
                store_unique_table((const char*)xml_start, xml_len, type, parsed_data, destIp, destPort);
            }
        }
    } 

    if(decompressed_buffer) {
        free(decompressed_buffer);
    }
}

/**
 * @brief Enhanced terminal payload processor with better ESG handling
 */
void process_terminal_payload(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort, int is_mmt, uint16_t packet_id) {
    if (is_esg_service(destIp, destPort) && toi > 0) {
        
        // Check if it looks like XML
        if(size > 5 && memcmp(buffer, "<?xml", 5) == 0) {
        } else if(size > 2 && buffer[0] == 0x1f && buffer[1] == 0x8b) {
        } else {
            
            // For non-GZIP, non-XML data that's too small or looks corrupted, skip it
            if (size < 100 || (size > 0 && buffer[0] > 0x7F && buffer[0] != 0x1f)) {
                return;
            }
        }
    }
    
    // Skip leading whitespace (but not for binary data!)
    if (size > 0 && buffer[0] < 0x80) {  // Only skip whitespace for ASCII-range data
        while (size > 0 && isspace(*buffer)) {
            buffer++;
            size--;
        }
    }
    if (size == 0) return;

    char source_id[512];
    snprintf(source_id, sizeof(source_id), "TOI=%u on %s:%s", toi, destIp, destPort);

    const uint8_t gzip_magic[] = {0x1f, 0x8b};
    if (size > 2 && memcmp(buffer, gzip_magic, 2) == 0) {
        int decompressed_size = 0, consumed_size = 0;
        char* decompressed_xml = decompress_gzip(buffer, size, &decompressed_size, &consumed_size);
        
        if (decompressed_xml && decompressed_size > 0) {
            // For ESG, find and skip garbage before XML
            if (is_esg_service(destIp, destPort)) {
                
                // Manually search for "<?xml" pattern (don't use strstr - it stops at null bytes)
                const char* xml_pattern = "<?xml";
                const char* xml_start = NULL;
                
                for (size_t i = 0; i < decompressed_size - 5; i++) {
                    if (memcmp(decompressed_xml + i, xml_pattern, 5) == 0) {
                        xml_start = decompressed_xml + i;
                        break;
                    }
                }
                
                // If no "<?xml", try finding "<Content"
                if (!xml_start) {
                    const char* content_pattern = "<Content";
                    for (size_t i = 0; i < decompressed_size - 8; i++) {
                        if (memcmp(decompressed_xml + i, content_pattern, 8) == 0) {
                            xml_start = decompressed_xml + i;
                            break;
                        }
                    }
                }
                
                if (xml_start && xml_start != decompressed_xml) {
                    size_t garbage_bytes = xml_start - decompressed_xml;
                    
                    // Create clean buffer
                    size_t clean_size = decompressed_size - garbage_bytes;
                    char* clean_xml = malloc(clean_size + 1);
                    if (clean_xml) {
                        memcpy(clean_xml, xml_start, clean_size);
                        clean_xml[clean_size] = '\0';
                        
                        // Replace the old buffer
                        free(decompressed_xml);
                        decompressed_xml = clean_xml;
                        decompressed_size = clean_size;
                        
                    }
                }
            
                
                // CRITICAL FIX: Check if there are multiple XML documents
                int xml_count = 0;
                const char* search_pos = decompressed_xml;
                const char* end_pos = decompressed_xml + decompressed_size;
                while (search_pos < end_pos) {
                    const char* found = memmem(search_pos, end_pos - search_pos, "<?xml", 5);
                    if (!found) break;
                    xml_count++;
                    search_pos = found + 5;
                }
                
                if (xml_count > 1) {
                    // Multiple documents - use the multi-document parser
                    process_multi_document_xml(decompressed_xml, decompressed_size, destIp, destPort, source_id);
                } else {
                    // Single document - parse normally
                    TableType type = TABLE_TYPE_UNKNOWN;
                    void* parsed_data = NULL;
                    
                    if (parse_xml(decompressed_xml, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                        store_unique_table(decompressed_xml, decompressed_size, type, parsed_data, destIp, destPort);
                        
                    }
                }
            } else {
                // Non-ESG service processing
                TableType type = TABLE_TYPE_UNKNOWN;
                void* parsed_data = NULL;
                
                if (parse_xml(decompressed_xml, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                    store_unique_table(decompressed_xml, decompressed_size, type, parsed_data, destIp, destPort);
                }
            }
            
            free(decompressed_xml);
        } else {
            if (is_esg_service(destIp, destPort)) {
                
                // Dump raw GZIP data for analysis
                char gzip_filename[256];
                snprintf(gzip_filename, sizeof(gzip_filename), "esg_toi_%u_gzip_raw.bin", toi);
                FILE* f_gzip = fopen(gzip_filename, "wb");
                if (f_gzip) {
                    fwrite(buffer, 1, size, f_gzip);
                    fclose(f_gzip);
                }
            }
        }
    } else if (size > 20) {
        
        
        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        if (parse_xml((const char*)buffer, size, &type, &parsed_data, source_id) == 0) {
            if(parsed_data) {
                store_unique_table((const char*)buffer, size, type, parsed_data, destIp, destPort);
                
            }
        }
    }
}

/**
 * @brief Parses a reassembled MIME object.
 */
void process_mime_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* boundary_str, const char* destIp, const char* destPort) {
    size_t boundary_len = strlen(boundary_str);
    
    // Validate we have a complete MIME structure
    char final_boundary[300];
    snprintf(final_boundary, sizeof(final_boundary), "%s--", boundary_str);
    
    const uint8_t* current_pos = buffer;
    size_t remaining_size = size;
    
    // Skip to the first boundary
    const uint8_t* first_boundary = memmem(current_pos, remaining_size, boundary_str, boundary_len);
    if (!first_boundary) {
        printf("ERROR: Could not find first boundary in MIME message\n");
        return;
    }
    
    current_pos = first_boundary;
    remaining_size = size - (current_pos - buffer);
    
    int part_count = 0;
    int max_parts = 100; // Safety limit
    
    while(part_count < max_parts) {
        const uint8_t* boundary_loc = memmem(current_pos, remaining_size, boundary_str, boundary_len);
        if(!boundary_loc) break;
        
        // Move past the boundary line (boundary + CRLF)
        const uint8_t* headers_start = boundary_loc + boundary_len;
        while (headers_start < buffer + size && (*headers_start == '\r' || *headers_start == '\n' || *headers_start == '-')) {
            headers_start++;
        }

        // Find the next boundary
        const uint8_t* next_boundary_loc = memmem(headers_start, size - (headers_start - buffer), boundary_str, boundary_len);
        if(!next_boundary_loc) {
            break;
        }

        // The part ends just before the next boundary (trim trailing CRLF)
        const uint8_t* part_end = next_boundary_loc;
        while (part_end > headers_start && (*(part_end - 1) == '\r' || *(part_end - 1) == '\n')) {
            part_end--;
        }

        if (part_end <= headers_start) {
            current_pos = next_boundary_loc;
            remaining_size = size - (current_pos - buffer);
            continue;
        }
        
        size_t part_len = part_end - headers_start;
        
        // Find the blank line that separates headers from content
        const char* header_sep = "\r\n\r\n";
        const uint8_t* payload_start = memmem(headers_start, part_len, header_sep, strlen(header_sep));

        if(payload_start) {
            payload_start += strlen(header_sep);
            size_t payload_len = part_end - payload_start;
            
            if (payload_len > 0) {
                part_count++;
                
                // Validate this looks like valid XML before processing
                int looks_valid = 0;
                if (payload_len > 5) {
                    if (memcmp(payload_start, "<?xml", 5) == 0 ||
                        memcmp(payload_start, "<S-TSID", 7) == 0 ||
                        memcmp(payload_start, "<MPD", 4) == 0 ||
                        memcmp(payload_start, "<FDT-", 5) == 0 ||
                        memcmp(payload_start, "<HELD", 5) == 0) {
                        looks_valid = 1;
                    }
                }
                
                if (!looks_valid) {
                    current_pos = next_boundary_loc;
                    remaining_size = size - (current_pos - buffer);
                    continue;
                }
                
                process_terminal_payload(toi, payload_start, payload_len, destIp, destPort, 0, 0);
            }
        } 

        current_pos = next_boundary_loc;
        remaining_size = size - (current_pos - buffer);
    }
    
}

/**
 * @brief FINAL: Top-level object processor. Scans a buffer for concatenated objects.
 */
void process_and_store_route_object(uint32_t toi, const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    if (size == 0) return;
    
    // Check for XML declarations
    int xml_count = 0;
    for (size_t i = 0; i < size - 5; i++) {
        if (memcmp(&buffer[i], "<?xml", 5) == 0) {
            xml_count++;
        }
    }

    // FIRST: Check for multipart MIME (but only if it looks like valid MIME)
    // MIME must start with either "Content-Type:" or have "multipart/related" near the beginning
    int looks_like_mime = 0;
    if (size > 20) {
        // Check if it starts with typical MIME headers
        if (memcmp(buffer, "Content-Type:", 13) == 0 ||
            memcmp(buffer, "Content-", 8) == 0 ||
            (size > 100 && memmem(buffer, 100, "multipart/related", 17) != NULL)) {
            looks_like_mime = 1;
        }
    }
    
    if (looks_like_mime) {
        const char* multipart_marker = "multipart/related";
        const uint8_t* multipart_loc = memmem(buffer, size > 500 ? 500 : size, multipart_marker, strlen(multipart_marker));
        
        if (multipart_loc) {
            
            const char* boundary_marker = "boundary=\"";
            const uint8_t* boundary_loc = memmem(buffer, size > 500 ? 500 : size, boundary_marker, strlen(boundary_marker));
            
            if (boundary_loc) {
                const char* boundary_val_start = (char*)boundary_loc + strlen(boundary_marker);
                const char* boundary_val_end = strchr(boundary_val_start, '"');
                
                if (boundary_val_end) {
                    char boundary_str[256];
                    size_t boundary_len = boundary_val_end - boundary_val_start;
                    snprintf(boundary_str, sizeof(boundary_str), "--%.*s", (int)boundary_len, boundary_val_start);
                    
                    // Count how many times this boundary appears
                    int boundary_count = 0;
                    const uint8_t* search_pos = buffer;
                    size_t search_remaining = size;
                    while (search_remaining > 0) {
                        const uint8_t* found = memmem(search_pos, search_remaining, boundary_str, strlen(boundary_str));
                        if (!found) break;
                        boundary_count++;
                        search_pos = found + strlen(boundary_str);
                        search_remaining = size - (search_pos - buffer);
                    }
                    
                    // Only process as MIME if we found at least 2 boundaries
                    if (boundary_count >= 2) {
                        process_mime_object(toi, buffer, size, boundary_str, destIp, destPort);
                        return;
                    }
                }
            }
        }
    }
    
    // Scanner logic with detailed logging
    const uint8_t* scan_pos = buffer;
    size_t remaining_size = size;
    int iteration = 0;

    while (remaining_size > 50) {
        iteration++;
        
        const char* fdt_marker = "<FDT-Instance";
        const char* stsid_marker = "<S-TSID";
        const char* mpd_marker = "<MPD";
        const char* held_marker = "<HELD";
        const char* usd_marker = "<BundleDescriptionROUTE";  // ADD THIS
        const char* meta_marker = "<metadataEnvelope";       // ADD THIS

        const uint8_t* fdt_start = memmem(scan_pos, remaining_size, fdt_marker, strlen(fdt_marker));
        const uint8_t* stsid_start = memmem(scan_pos, remaining_size, stsid_marker, strlen(stsid_marker));
        const uint8_t* mpd_start = memmem(scan_pos, remaining_size, mpd_marker, strlen(mpd_marker));
        const uint8_t* held_start = memmem(scan_pos, remaining_size, held_marker, strlen(held_marker));
        const uint8_t* usd_start = memmem(scan_pos, remaining_size, usd_marker, strlen(usd_marker));      // ADD THIS
        const uint8_t* meta_start = memmem(scan_pos, remaining_size, meta_marker, strlen(meta_marker));   // ADD THIS
        
        const uint8_t* next_obj_start = NULL;
        int next_obj_type = -1;
        
        if (fdt_start) { next_obj_start = fdt_start; next_obj_type = 1; }
        if (stsid_start && (!next_obj_start || stsid_start < next_obj_start)) { 
            next_obj_start = stsid_start; next_obj_type = 2;
        }
        if (mpd_start && (!next_obj_start || mpd_start < next_obj_start)) { 
            next_obj_start = mpd_start; next_obj_type = 3;
        }
        if (held_start && (!next_obj_start || held_start < next_obj_start)) { 
            next_obj_start = held_start; next_obj_type = 4;
        }
        if (usd_start && (!next_obj_start || usd_start < next_obj_start)) {   // ADD THIS
            next_obj_start = usd_start; next_obj_type = 5;
        }
        if (meta_start && (!next_obj_start || meta_start < next_obj_start)) { // ADD THIS
            next_obj_start = meta_start; next_obj_type = 6;
        }

        if (!next_obj_start) {
            if (scan_pos == buffer && remaining_size > 0) {
                process_terminal_payload(toi, scan_pos, remaining_size, destIp, destPort, 0, 0);
            }
            break;
        }
        
        // Check gap before next object
        if (next_obj_start > scan_pos) {
            size_t gap_len = next_obj_start - scan_pos;
            
            int is_mime_artifact = 0;
            if (gap_len > 6 && memmem(scan_pos, gap_len, "------", 6) != NULL) {
                is_mime_artifact = 1;
            }
            if (gap_len > 13 && memmem(scan_pos, gap_len, "Content-Type:", 13) != NULL) {
                is_mime_artifact = 1;
            }
            
            if (is_mime_artifact) {
            } else if (gap_len > 20) {
                process_terminal_payload(toi, scan_pos, gap_len, destIp, destPort, 0, 0);
            }
        }
        
        scan_pos = next_obj_start;
        remaining_size = size - (scan_pos - buffer);

        // Find end marker for this object type
        const char* end_marker = NULL;
        
        if (next_obj_type == 1) { 
            end_marker = "</FDT-Instance>";
        } else if (next_obj_type == 2) { 
            end_marker = "</S-TSID>";
        } else if (next_obj_type == 3) { 
            end_marker = "</MPD>";
        } else if (next_obj_type == 4) { 
            end_marker = "</HELD>";
        } else if (next_obj_type == 5) {                    // ADD THIS
            end_marker = "</BundleDescriptionROUTE>";
        } else if (next_obj_type == 6) {                    // ADD THIS
            end_marker = "</metadataEnvelope>";
        }
        
        if (end_marker) {
            const uint8_t* obj_end = memmem(scan_pos, remaining_size, end_marker, strlen(end_marker));
            if (obj_end) {
                obj_end += strlen(end_marker);
                size_t obj_len = obj_end - scan_pos;
                
                // Validate it starts with <?xml or proper tag
                if (obj_len > 5) {
                    if (memcmp(scan_pos, "<?xml", 5) == 0 || memcmp(scan_pos, "<", 1) == 0) {
                        process_terminal_payload(toi, scan_pos, obj_len, destIp, destPort, 0, 0);
                    }
                }
                
                scan_pos = obj_end;
                remaining_size = size - (scan_pos - buffer);
                continue;
            }
        }
        
        process_terminal_payload(toi, scan_pos, remaining_size, destIp, destPort, 0, 0);
        break;
    }
}

void reclassify_data_usage_after_slt() {
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry = &g_data_usage[i];
        
        // Skip LLS entries
        if (entry->is_lls) continue;
        
        // Find matching service destination
        ServiceDestination* dest_info = NULL;
        for (int j = 0; j < g_service_dest_count; j++) {
            if (strcmp(g_service_dests[j].destinationIpStr, entry->destinationIp) == 0 &&
                strcmp(g_service_dests[j].destinationPortStr, entry->destinationPort) == 0) {
                dest_info = &g_service_dests[j];
                break;
            }
        }
        
        if (dest_info) {
            // Update stream type and signaling flag based on SLT info
            if (strcmp(dest_info->protocol, "1") == 0) {
                strcpy(entry->stream_type, "ROUTE");
                entry->is_signaling = (entry->tsi_or_packet_id == 0);
            } else if (strcmp(dest_info->protocol, "2") == 0) {
                strcpy(entry->stream_type, "MMT");
                entry->is_signaling = (entry->tsi_or_packet_id == 0);
            }
            
            // Now generate enhanced description with full signaling table access
            const char* new_description = get_enhanced_stream_description(
                entry->destinationIp, entry->destinationPort, 
                entry->tsi_or_packet_id, entry->stream_type, entry->is_lls);
            
            strncpy(entry->description, new_description, sizeof(entry->description) - 1);
            entry->description[sizeof(entry->description) - 1] = '\0';
        }
    }
}

/**
 * @brief Processes the UDP payload of an LLS packet.
 */
void process_lls_payload(const u_char *payload, int len) {
    record_data_usage("224.0.23.60", "4937", 0, len, "ATSC 3.0 LLS (Low Level Signaling)");
    
    const u_char *payload_start = payload;
    const u_char *current_pos = payload;
    int remaining_len = len;
    int fragments_found = 0;

    while (remaining_len > 10) { 
        const u_char *gzip_header = NULL;
        for (int i = 0; i < remaining_len - 1; ++i) {
            if (current_pos[i] == 0x1f && current_pos[i+1] == 0x8b) {
                gzip_header = current_pos + i;
                break;
            }
        }

        if (gzip_header) {
            fragments_found++;
            
            int decompressed_size = 0;
            int consumed_size = 0;
            char *xml_content = decompress_gzip(gzip_header, remaining_len - (gzip_header - current_pos), &decompressed_size, &consumed_size);

            if (xml_content && consumed_size > 0) {
                TableType type = TABLE_TYPE_UNKNOWN;
                void* parsed_data = NULL;
                if(parse_xml(xml_content, decompressed_size, &type, &parsed_data, "LLS Global") == 0 && parsed_data) {
                    if(type == TABLE_TYPE_SLT) {
                        store_slt_destinations((SltData*)parsed_data);
                    }
                    store_unique_table(xml_content, decompressed_size, type, parsed_data, NULL, NULL);
                    if(type == TABLE_TYPE_SLT) {
                        store_slt_destinations((SltData*)parsed_data);
                    }
                }
                free(xml_content);
                
                current_pos = gzip_header + consumed_size;
                remaining_len = len - (current_pos - payload_start);

            } else {
                break;
            }
        } else {
            break;
        }
    }

    if (fragments_found > 0 && remaining_len > 10) {
        SignatureData* sig_data = calloc(1, sizeof(SignatureData));
        if(sig_data) {
            sig_data->signature_len = remaining_len;
            char sig_id[256];
            snprintf(sig_id, sizeof(sig_id), "<Signature len=\"%d\"/>", remaining_len);
            store_unique_table(sig_id, strlen(sig_id), TABLE_TYPE_SIGNATURE, sig_data, NULL, NULL);
        }
    }

    if (fragments_found == 0) {
        TableType type = TABLE_TYPE_UNKNOWN;
        void* parsed_data = NULL;
        if(parse_xml((const char*)payload, len, &type, &parsed_data, "LLS Global") == 0 && parsed_data) {
             if(type == TABLE_TYPE_SLT) {
                store_slt_destinations((SltData*)parsed_data);
            }
            store_unique_table((const char*)payload, len, type, parsed_data, NULL, NULL);
        }
    }
}

void store_slt_destinations(SltData* slt_data) {
    if(!slt_data) {
        return;
    }

    ServiceInfo* service = slt_data->head;
    int services_processed = 0;
    while(service) {
        services_processed++;
        
        // Store destinations for services that have SLS streams OR are ESG services
        if((strlen(service->slsDestinationIpAddress) > 0 || strcmp(service->serviceCategory, "4") == 0) && 
           g_service_dest_count < MAX_SERVICES) {
            
            struct in_addr dest_ip;
            if (inet_aton(service->slsDestinationIpAddress, &dest_ip) == 0) {
                service = service->next;
                continue;
            }
            
            uint16_t dest_port = atoi(service->slsDestinationUdpPort);
            if (dest_port == 0) {
                service = service->next;
                continue;
            }

            int found = 0;
            for(int i = 0; i < g_service_dest_count; i++) {
                if(g_service_dests[i].ip_addr.s_addr == dest_ip.s_addr && g_service_dests[i].port == dest_port) {
                    found = 1;
                    break;
                }
            }

            if(!found) {
                
                g_service_dests[g_service_dest_count].ip_addr = dest_ip;
                g_service_dests[g_service_dest_count].port = dest_port;
                strncpy(g_service_dests[g_service_dest_count].destinationIpStr, service->slsDestinationIpAddress, sizeof(g_service_dests[0].destinationIpStr) - 1);
                g_service_dests[g_service_dest_count].destinationIpStr[sizeof(g_service_dests[0].destinationIpStr) - 1] = '\0';
                strncpy(g_service_dests[g_service_dest_count].destinationPortStr, service->slsDestinationUdpPort, sizeof(g_service_dests[0].destinationPortStr) - 1);
                g_service_dests[g_service_dest_count].destinationPortStr[sizeof(g_service_dests[0].destinationPortStr) - 1] = '\0';
                strncpy(g_service_dests[g_service_dest_count].protocol, service->slsProtocol, sizeof(g_service_dests[0].protocol) - 1);
                g_service_dests[g_service_dest_count].protocol[sizeof(g_service_dests[0].protocol) - 1] = '\0';
                g_service_dests[g_service_dest_count].mmtSignalingPacketId = atoi(service->slsMmtpPacketId);
                
                strncpy(g_service_dests[g_service_dest_count].serviceCategory, service->serviceCategory, sizeof(g_service_dests[0].serviceCategory) - 1);
                g_service_dests[g_service_dest_count].serviceCategory[sizeof(g_service_dests[0].serviceCategory) - 1] = '\0';
                g_service_dests[g_service_dest_count].isEsgService = (strcmp(service->serviceCategory, "4") == 0) ? 1 : 0;
                
                g_service_dest_count++;
            }
        }
        service = service->next;
    }
}

/**
 * @brief Checks if a table is unique and stores it if so.
 */
void store_unique_table(const char* content, int len, TableType type, void* parsed_data, const char* destIp, const char* destPort) {
    // Validate completeness for critical table types
    if (type == TABLE_TYPE_MPD || type == TABLE_TYPE_STSID) {
        // Check if content ends properly
        const char* last_200 = content + (len > 200 ? len - 200 : 0);
        size_t check_len = len > 200 ? 200 : len;
        
        if (type == TABLE_TYPE_MPD && !memmem(last_200, check_len, "</MPD>", 6)) {
            printf("WARN: Rejecting incomplete MPD (no closing tag), len=%d\n", len);
            printf("Last 200 chars: %.*s\n", (int)check_len, last_200);
            free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
            return;
        }
        
        if (type == TABLE_TYPE_STSID && !memmem(last_200, check_len, "</S-TSID>", 9)) {
            printf("WARN: Rejecting incomplete S-TSID (no closing tag), len=%d, dest=%s:%s\n", 
                   len, destIp ? destIp : "N/A", destPort ? destPort : "N/A");
            printf("Last 200 chars: %.*s\n", (int)check_len, last_200);
            free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
            return;
        }
    }
    
    
    if (g_lls_table_count >= MAX_TABLES) {
        fprintf(stderr, "Warning: Maximum number of unique tables reached.\n");
        free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
        return;
    }

    for (int i = 0; i < g_lls_table_count; i++) {
         if (g_lls_tables[i].type == type) {
            int ip_match = (destIp && strlen(destIp) > 0) ? 
                           (strcmp(g_lls_tables[i].destinationIp, destIp) == 0) : 
                           (strlen(g_lls_tables[i].destinationIp) == 0);
            int port_match = (destPort && strlen(destPort) > 0) ? 
                             (strcmp(g_lls_tables[i].destinationPort, destPort) == 0) : 
                             (strlen(g_lls_tables[i].destinationPort) == 0);

            if (ip_match && port_match && strncmp(g_lls_tables[i].content_id, content, len) == 0 && strlen(g_lls_tables[i].content_id) == len) {
                free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
                return; 
            }
        }
    }

    LlsTable* new_table = &g_lls_tables[g_lls_table_count];
    new_table->content_id = strndup(content, len);
    if (!new_table->content_id) {
        perror("Failed to allocate memory for content ID");
        free_parsed_data(&(LlsTable){ .type = type, .parsed_data = parsed_data });
        return;
    }
    new_table->parsed_data = parsed_data;
    new_table->type = type;
    if (destIp) {
        strncpy(new_table->destinationIp, destIp, sizeof(new_table->destinationIp) - 1);
        new_table->destinationIp[sizeof(new_table->destinationIp) - 1] = '\0';
    } else {
        new_table->destinationIp[0] = '\0';
    }
    if (destPort) {
        strncpy(new_table->destinationPort, destPort, sizeof(new_table->destinationPort) - 1);
        new_table->destinationPort[sizeof(new_table->destinationPort) - 1] = '\0';
    } else {
        new_table->destinationPort[0] = '\0';
    }

    g_lls_table_count++;
}

void process_multi_document_xml(const char* xml_data, size_t size, const char* destIp, const char* destPort, const char* source_id) {
    const char* current_pos = xml_data;
    size_t remaining = size;
    int doc_count = 0;
    const char* xml_marker = "<?xml";
    
    while (remaining > 10) {
        // Find next XML declaration using memmem (handles null bytes)
        const char* next_doc = memmem(current_pos, remaining, xml_marker, 5);
        if (!next_doc) break;
        
        // Find the end of this document (start of next one, or end of buffer)
        const char* doc_end;
        size_t search_size = remaining - (next_doc - current_pos + 5);
        const char* next_xml = memmem(next_doc + 5, search_size, xml_marker, 5);
        
        if (next_xml) {
            doc_end = next_xml;
        } else {
            doc_end = xml_data + size;
        }
        
        size_t doc_len = doc_end - next_doc;
        if (doc_len > 10) {
            doc_count++;
            
            TableType type = TABLE_TYPE_UNKNOWN;
            void* parsed_data = NULL;
            if (parse_xml(next_doc, doc_len, &type, &parsed_data, source_id) == 0 && parsed_data) {
                store_unique_table(next_doc, doc_len, type, parsed_data, destIp, destPort);
            }
        }
        
        current_pos = doc_end;
        remaining = size - (current_pos - xml_data);
    }
}

/**
 * @brief Parses XML content and routes to the correct specific parser.
 * @return 0 on success (even if no data is extracted), -1 on a true parsing failure.
 */
int parse_xml(const char* xml_content, int len, TableType* type, void** parsed_data_out, const char* source_identifier) {
    *parsed_data_out = NULL;
    *type = TABLE_TYPE_UNKNOWN;

    xmlDocPtr doc = xmlReadMemory(xml_content, len, "noname.xml", NULL, XML_PARSE_RECOVER | XML_PARSE_NOWARNING | XML_PARSE_NOERROR);

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (root == NULL) {
        xmlFreeDoc(doc);
        return -1; // True failure
    }
    
    if (xmlStrcmp(root->name, (const xmlChar *)"SLT") == 0) {
        *type = TABLE_TYPE_SLT;
        *parsed_data_out = parse_slt(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"SystemTime") == 0) {
        *type = TABLE_TYPE_SYSTEM_TIME;
        *parsed_data_out = parse_system_time(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"UCT") == 0) {
        *type = TABLE_TYPE_UCT;
        *parsed_data_out = parse_uct(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"CertificationData") == 0) {
        *type = TABLE_TYPE_CDT;
        *parsed_data_out = parse_cdt(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"UDST") == 0) {
        *type = TABLE_TYPE_UDST;
        *parsed_data_out = parse_udst(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"FDT-Instance") == 0) {
        *type = TABLE_TYPE_FDT;
        *parsed_data_out = parse_fdt(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"S-TSID") == 0) {
        *type = TABLE_TYPE_STSID;
        *parsed_data_out = parse_stsid(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"MPD") == 0) {
        *type = TABLE_TYPE_MPD;
        *parsed_data_out = parse_mpd(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"HELD") == 0) {
        *type = TABLE_TYPE_HELD;
        *parsed_data_out = parse_held(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Service") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    } else if (xmlStrcmp(root->name, (const xmlChar *)"Program") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"ServiceGuideDeliveryDescriptor") == 0) {
        *type = TABLE_TYPE_SGDD;
        *parsed_data_out = parse_sgdd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"Schedule") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"ServiceBundle") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"ESG") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"Content") == 0) {
        *type = TABLE_TYPE_ESG_FRAGMENT;
        *parsed_data_out = parse_esg_service_fragment(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"BundleDescriptionROUTE") == 0) {
        *type = TABLE_TYPE_USER_SERVICE_DESCRIPTION;
        *parsed_data_out = parse_user_service_description(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"BundleDescriptionMMT") == 0) {
        *type = TABLE_TYPE_USBD;
        *parsed_data_out = parse_usbd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"UserServiceDescription") == 0) {
        *type = TABLE_TYPE_USD;
        *parsed_data_out = parse_usd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"USD") == 0) {
        *type = TABLE_TYPE_USD;
        *parsed_data_out = parse_usd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"DWD") == 0) {
        *type = TABLE_TYPE_DWD;
        *parsed_data_out = parse_dwd(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"metadataEnvelope") == 0) {
        *type = TABLE_TYPE_SERVICE_SIGNALING;
        *parsed_data_out = parse_service_signaling(doc);
    }
    else if (xmlStrcmp(root->name, (const xmlChar *)"MP_Table") == 0) {
        *type = TABLE_TYPE_MP_TABLE_XML;
        *parsed_data_out = parse_mp_table(doc);
    }
    else {
        printf("--> INFO: Encountered unrecognized XML root element: '%s'\n", root->name);
    }

    xmlFreeDoc(doc);
    return 0; // Success
}

/**
 * @brief Parses an FDT-Instance from a given XML node.
 * This was refactored from parse_fdt to allow parsing of embedded FDTs.
 */
FDTInstanceData* parse_fdt_from_node(xmlNodePtr fdt_node) {
    if (!fdt_node) return NULL;

    FDTInstanceData* fdt_data = calloc(1, sizeof(FDTInstanceData));
    if (!fdt_data) return NULL;

    xmlChar* prop = xmlGetProp(fdt_node, (const xmlChar *)"Expires");
    if(prop) { 
        strncpy(fdt_data->expires, (char*)prop, sizeof(fdt_data->expires)-1); 
        xmlFree(prop); 
    }

    xmlNodePtr cur_node = fdt_node->children;
    FDTFileInfo* current_file_tail = NULL;
    int file_count = 0;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, (const xmlChar *)"File") == 0 ||
                xmlStrcmp(cur_node->name, (const xmlChar *)"fdt:File") == 0) {
                
                FDTFileInfo* file_info = calloc(1, sizeof(FDTFileInfo));
                if (!file_info) continue;
                
                prop = xmlGetProp(cur_node, (const xmlChar *)"Content-Location");
                if(prop) { strncpy(file_info->contentLocation, (char*)prop, sizeof(file_info->contentLocation)-1); xmlFree(prop); }
                
                prop = xmlGetProp(cur_node, (const xmlChar *)"TOI");
                if(prop) { strncpy(file_info->toi, (char*)prop, sizeof(file_info->toi)-1); xmlFree(prop); }

                prop = xmlGetProp(cur_node, (const xmlChar *)"Content-Length");
                if(prop) { strncpy(file_info->contentLength, (char*)prop, sizeof(file_info->contentLength)-1); xmlFree(prop); }
                
                prop = xmlGetProp(cur_node, (const xmlChar *)"Content-Type");
                if(prop) { strncpy(file_info->contentType, (char*)prop, sizeof(file_info->contentType)-1); xmlFree(prop); }

                if (fdt_data->head == NULL) {
                    fdt_data->head = file_info;
                    current_file_tail = file_info;
                } else {
                    current_file_tail->next = file_info;
                    current_file_tail = file_info;
                }
                file_count++;
            }
        }
        cur_node = cur_node->next;
    }
    
    if (file_count > 0) {
    } else {
        free(fdt_data);
        fdt_data = NULL;
    }

    return fdt_data;
}


/**
 * @brief Wrapper for parse_fdt_from_node to parse a whole document where FDT is the root.
 */
FDTInstanceData* parse_fdt(xmlDocPtr doc) {
    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (xmlStrcmp(root->name, (const xmlChar *)"FDT-Instance") == 0) {
        return parse_fdt_from_node(root);
    }
    return NULL;
}


/**
 * @brief Iterates through the children of a node and attempts to parse them
 * as known standalone table types (like FDT-Instance).
 */
void parse_embedded_children(xmlNodePtr parent_node, const char* destIp, const char* destPort) {
    xmlNodePtr cur_node = NULL;
    for (cur_node = parent_node; cur_node; cur_node = cur_node->next) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, (const xmlChar *)"FDT-Instance") == 0) {
                FDTInstanceData* fdt_data = parse_fdt_from_node(cur_node);
                if (fdt_data) {
                    xmlBufferPtr buf = xmlBufferCreate();
                    xmlNodeDump(buf, cur_node->doc, cur_node, 0, 1);
                    store_unique_table((const char*)buf->content, buf->use, TABLE_TYPE_FDT, fdt_data, destIp, destPort);
                    xmlBufferFree(buf);
                }
            }
            // Future: Add checks for other embedded types like MPD here if needed
        }
        parse_embedded_children(cur_node->children, destIp, destPort);
    }
}

/**
 * @brief Parses a DASH MPD XML document into MpdData struct.
 */
MpdData* parse_mpd(xmlDocPtr doc) {
    MpdData* mpd_data = calloc(1, sizeof(MpdData));
    if (!mpd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlChar* prop;
    
    prop = xmlGetProp(root, (const xmlChar *)"publishTime");
    if(prop) { strncpy(mpd_data->publishTime, (char*)prop, sizeof(mpd_data->publishTime)-1); xmlFree(prop); }
    prop = xmlGetProp(root, (const xmlChar *)"profiles");
    if(prop) { strncpy(mpd_data->profiles, (char*)prop, sizeof(mpd_data->profiles)-1); xmlFree(prop); }
    prop = xmlGetProp(root, (const xmlChar *)"type");
    if(prop) { strncpy(mpd_data->type, (char*)prop, sizeof(mpd_data->type)-1); xmlFree(prop); }
    prop = xmlGetProp(root, (const xmlChar *)"minBufferTime");
    if(prop) { strncpy(mpd_data->minBufferTime, (char*)prop, sizeof(mpd_data->minBufferTime)-1); xmlFree(prop); }


    xmlNodePtr period_node = root->children;
    MpdAdaptationSet* current_as_tail = NULL;

    // Find the first Period node
    while(period_node != NULL && (period_node->type != XML_ELEMENT_NODE || xmlStrcmp(period_node->name, (const xmlChar *)"Period") != 0)) {
        period_node = period_node->next;
    }
    if(!period_node) { free(mpd_data); return NULL; }

// Iterate through AdaptationSet nodes within the Period
    xmlNodePtr as_node = period_node->children;
    while(as_node != NULL) {
        if(as_node->type == XML_ELEMENT_NODE && xmlStrcmp(as_node->name, (const xmlChar *)"AdaptationSet") == 0) {
            MpdAdaptationSet* as = calloc(1, sizeof(MpdAdaptationSet));
            if(!as) continue;

            prop = xmlGetProp(as_node, (const xmlChar *)"contentType");
            if(prop) { strncpy(as->contentType, (char*)prop, sizeof(as->contentType)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"lang");
            if(prop) { strncpy(as->lang, (char*)prop, sizeof(as->lang)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"mimeType");
            if(prop) { strncpy(as->mimeType, (char*)prop, sizeof(as->mimeType)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"par");
            if(prop) { strncpy(as->par, (char*)prop, sizeof(as->par)-1); xmlFree(prop); }

            // NEW: Parse AdaptationSet-level attributes that should be inherited by Representations
            char as_codecs[128] = "";
            char as_width[16] = "";
            char as_height[16] = "";
            char as_frameRate[16] = "";
            char as_audioSamplingRate[16] = "";
            
            prop = xmlGetProp(as_node, (const xmlChar *)"codecs");
            if(prop) { strncpy(as_codecs, (char*)prop, sizeof(as_codecs)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"width");
            if(prop) { strncpy(as_width, (char*)prop, sizeof(as_width)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"height");
            if(prop) { strncpy(as_height, (char*)prop, sizeof(as_height)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"frameRate");
            if(prop) { strncpy(as_frameRate, (char*)prop, sizeof(as_frameRate)-1); xmlFree(prop); }
            prop = xmlGetProp(as_node, (const xmlChar *)"audioSamplingRate");
            if(prop) { strncpy(as_audioSamplingRate, (char*)prop, sizeof(as_audioSamplingRate)-1); xmlFree(prop); }

            // Find SegmentTemplate at the AdaptationSet level
            SegmentTemplateData as_template = {0};
            xmlNodePtr temp_node = as_node->children;
            while(temp_node != NULL) {
                 if(temp_node->type == XML_ELEMENT_NODE && xmlStrcmp(temp_node->name, (const xmlChar *)"SegmentTemplate") == 0) {
                    prop = xmlGetProp(temp_node, (const xmlChar *)"initialization");
                    if(prop) { strncpy(as_template.initialization, (char*)prop, sizeof(as_template.initialization)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"media");
                    if(prop) { strncpy(as_template.media, (char*)prop, sizeof(as_template.media)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"timescale");
                    if(prop) { strncpy(as_template.timescale, (char*)prop, sizeof(as_template.timescale)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"startNumber");
                    if(prop) { strncpy(as_template.startNumber, (char*)prop, sizeof(as_template.startNumber)-1); xmlFree(prop); }
                    prop = xmlGetProp(temp_node, (const xmlChar *)"duration");
                    if(prop) { strncpy(as_template.duration, (char*)prop, sizeof(as_template.duration)-1); xmlFree(prop); }
                    
                    xmlNodePtr timeline_node = temp_node->children;
                    SegmentTimelineS* current_s_tail = NULL;
                     while(timeline_node != NULL) {
                        if(timeline_node->type == XML_ELEMENT_NODE && xmlStrcmp(timeline_node->name, (const xmlChar*)"SegmentTimeline") == 0) {
                            xmlNodePtr s_node = timeline_node->children;
                            while(s_node != NULL) {
                                if(s_node->type == XML_ELEMENT_NODE && xmlStrcmp(s_node->name, (const xmlChar*)"S") == 0) {
                                    SegmentTimelineS* s_elem = calloc(1, sizeof(SegmentTimelineS));
                                    if(s_elem) {
                                        prop = xmlGetProp(s_node, (const xmlChar*)"t");
                                        if(prop) { strncpy(s_elem->t, (char*)prop, sizeof(s_elem->t)-1); xmlFree(prop); }
                                        prop = xmlGetProp(s_node, (const xmlChar*)"d");
                                        if(prop) { strncpy(s_elem->d, (char*)prop, sizeof(s_elem->d)-1); xmlFree(prop); }
                                        prop = xmlGetProp(s_node, (const xmlChar*)"r");
                                        if(prop) { strncpy(s_elem->r, (char*)prop, sizeof(s_elem->r)-1); xmlFree(prop); }
                                        
                                        if(as_template.timeline == NULL) {
                                            as_template.timeline = s_elem;
                                            current_s_tail = s_elem;
                                        } else {
                                            current_s_tail->next = s_elem;
                                            current_s_tail = s_elem;
                                        }
                                    }
                                }
                                s_node = s_node->next;
                            }
                            break;
                        }
                        timeline_node = timeline_node->next;
                     }
                    break;
                 }
                 temp_node = temp_node->next;
            }

            // Parse ContentProtection elements for DRM
            DrmInfo* adaptationset_drm = NULL;
            DrmInfo* as_drm_tail = NULL;

            xmlNodePtr as_child = as_node->children;
            while(as_child != NULL) {
                if(as_child->type == XML_ELEMENT_NODE && 
                xmlStrcmp(as_child->name, (const xmlChar*)"ContentProtection") == 0) {
                    
                    DrmInfo* drm = parse_drm_content_protection(as_child);
                    if (drm) {
                        if (adaptationset_drm == NULL) {
                            adaptationset_drm = drm;
                            as_drm_tail = drm;
                        } else {
                            as_drm_tail->next = drm;
                            as_drm_tail = drm;
                        }
                    }
                }
                as_child = as_child->next;
            }

            // Parse Representation nodes
            xmlNodePtr rep_node = as_node->children;
            MpdRepresentation* current_rep_tail = NULL;
            while(rep_node != NULL) {
                if(rep_node->type == XML_ELEMENT_NODE && xmlStrcmp(rep_node->name, (const xmlChar *)"Representation") == 0) {
                    MpdRepresentation* rep = calloc(1, sizeof(MpdRepresentation));
                    if(!rep) continue;
                    
                    memcpy(&rep->segmentTemplate, &as_template, sizeof(SegmentTemplateData));

                    // Parse Representation-level attributes with inheritance from AdaptationSet
                    prop = xmlGetProp(rep_node, (const xmlChar *)"id");
                    if(prop) { strncpy(rep->id, (char*)prop, sizeof(rep->id)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"codecs");
                    if(prop) { 
                        strncpy(rep->codecs, (char*)prop, sizeof(rep->codecs)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_codecs) > 0) {
                        strncpy(rep->codecs, as_codecs, sizeof(rep->codecs)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"bandwidth");
                    if(prop) { strncpy(rep->bandwidth, (char*)prop, sizeof(rep->bandwidth)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"width");
                    if(prop) { 
                        strncpy(rep->width, (char*)prop, sizeof(rep->width)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_width) > 0) {
                        strncpy(rep->width, as_width, sizeof(rep->width)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"height");
                    if(prop) { 
                        strncpy(rep->height, (char*)prop, sizeof(rep->height)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_height) > 0) {
                        strncpy(rep->height, as_height, sizeof(rep->height)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"frameRate");
                    if(prop) { 
                        strncpy(rep->frameRate, (char*)prop, sizeof(rep->frameRate)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_frameRate) > 0) {
                        strncpy(rep->frameRate, as_frameRate, sizeof(rep->frameRate)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"audioSamplingRate");
                    if(prop) { 
                        strncpy(rep->audioSamplingRate, (char*)prop, sizeof(rep->audioSamplingRate)-1); 
                        xmlFree(prop); 
                    } else if(strlen(as_audioSamplingRate) > 0) {
                        strncpy(rep->audioSamplingRate, as_audioSamplingRate, sizeof(rep->audioSamplingRate)-1);
                    }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"sar");
                    if(prop) { strncpy(rep->sar, (char*)prop, sizeof(rep->sar)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(rep_node, (const xmlChar *)"scanType");
                    if(prop) { strncpy(rep->scanType, (char*)prop, sizeof(rep->scanType)-1); xmlFree(prop); }

                    prop = xmlGetProp(rep_node, (const xmlChar *)"audioChannelCount");
                    if(prop) { strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1); xmlFree(prop); }
                    
                    // Always check for AudioChannelConfiguration elements (both in Representation and AdaptationSet)
                    if (strlen(rep->audioChannelCount) == 0) {
                        // First check within the Representation
                        xmlNodePtr audio_config_node = rep_node->children;
                        while(audio_config_node != NULL) {
                            if(audio_config_node->type == XML_ELEMENT_NODE && 
                               xmlStrcmp(audio_config_node->name, (const xmlChar*)"AudioChannelConfiguration") == 0) {
                                prop = xmlGetProp(audio_config_node, (const xmlChar*)"value");
                                if(prop) { 
                                    // Handle AC-4 hex encoding for channel configuration
                                    if (strlen((char*)prop) == 6) {
                                        // 6-character hex string - decode according to Dolby AC-4 spec
                                        unsigned int hex_value = 0;
                                        if (sscanf((char*)prop, "%06x", &hex_value) == 1) {
                                            // Map AC-4 hex values to channel counts based on Dolby spec
                                            switch (hex_value) {
                                                case 0x000002: strcpy(rep->audioChannelCount, "1"); break;   // 1.0 (C)
                                                case 0x000001: strcpy(rep->audioChannelCount, "2"); break;   // 2.0 (L, R)
                                                case 0x000047: strcpy(rep->audioChannelCount, "6"); break;   // 5.1 (L, R, C, LFE, Ls, Rs)
                                                case 0x0000C7: strcpy(rep->audioChannelCount, "8"); break;   // 5.1.2 (L, R, C, LFE, Ls, Rs, TL, TR)
                                                case 0x000077: strcpy(rep->audioChannelCount, "10"); break;  // 5.1.4 (L, R, C, LFE, Ls, Rs, Tfl, Tfr, Tbl, Tbr)
                                                case 0x0000CF: strcpy(rep->audioChannelCount, "10"); break;  // 7.1.2 (L, R, C, LFE, Ls, Rs, Lb, Rb, TL, TR)
                                                case 0x00007F: strcpy(rep->audioChannelCount, "12"); break;  // 7.1.4 (L, R, C, LFE, Ls, Rs, Lb, Rb, Tfl, Tfr, Tbl, Tbr)
                                                default:
                                                    // For unknown hex values, store the original hex string
                                                    strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1);
                                                    break;
                                            }
                                        } else {
                                            // Invalid hex format, store as-is
                                            strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1);
                                        }
                                    } else {
                                        // Standard decimal integer format
                                        strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1);
                                    }
                                    xmlFree(prop); 
                                    break;
                                }
                            }
                            audio_config_node = audio_config_node->next;
                        }
                        
                        // If still not found, check in the parent AdaptationSet
                        if (strlen(rep->audioChannelCount) == 0) {
                            xmlNodePtr as_audio_config = as_node->children;
                            while(as_audio_config != NULL) {
                                if(as_audio_config->type == XML_ELEMENT_NODE && 
                                   xmlStrcmp(as_audio_config->name, (const xmlChar*)"AudioChannelConfiguration") == 0) {
                                    prop = xmlGetProp(as_audio_config, (const xmlChar*)"value");
                                    if(prop) { 
                                        // Handle AC-4 hex encoding for channel configuration
                                        if (strlen((char*)prop) == 6) {
                                            // 6-character hex string - decode according to Dolby AC-4 spec
                                            unsigned int hex_value = 0;
                                            if (sscanf((char*)prop, "%06x", &hex_value) == 1) {
                                                // Map AC-4 hex values to channel counts based on Dolby spec
                                                switch (hex_value) {
                                                    case 0x000002: strcpy(rep->audioChannelCount, "1"); break;   // 1.0 (C)
                                                    case 0x000001: strcpy(rep->audioChannelCount, "2"); break;   // 2.0 (L, R)
                                                    case 0x000047: strcpy(rep->audioChannelCount, "6"); break;   // 5.1 (L, R, C, LFE, Ls, Rs)
                                                    case 0x0000C7: strcpy(rep->audioChannelCount, "8"); break;   // 5.1.2 (L, R, C, LFE, Ls, Rs, TL, TR)
                                                    case 0x000077: strcpy(rep->audioChannelCount, "10"); break;  // 5.1.4 (L, R, C, LFE, Ls, Rs, Tfl, Tfr, Tbl, Tbr)
                                                    case 0x0000CF: strcpy(rep->audioChannelCount, "10"); break;  // 7.1.2 (L, R, C, LFE, Ls, Rs, Lb, Rb, TL, TR)
                                                    case 0x00007F: strcpy(rep->audioChannelCount, "12"); break;  // 7.1.4 (L, R, C, LFE, Ls, Rs, Lb, Rb, Tfl, Tfr, Tbl, Tbr)
                                                    default:
                                                        // For unknown hex values, store the original hex string
                                                        strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1);
                                                        break;
                                                }
                                            } else {
                                                // Invalid hex format, store as-is
                                                strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1);
                                            }
                                        } else {
                                            // Standard decimal integer format
                                            strncpy(rep->audioChannelCount, (char*)prop, sizeof(rep->audioChannelCount)-1);
                                        }
                                        xmlFree(prop); 
                                        break;
                                    }
                                }
                                as_audio_config = as_audio_config->next;
                            }
                        }
                    }
                    
                    // Calculate display aspect ratio
                    if(strlen(rep->width) > 0 && strlen(rep->height) > 0) {
                        int width = atoi(rep->width);
                        int height = atoi(rep->height);
                        double par = 1.0;
                        
                        if(strlen(rep->sar) > 0) {
                            char* colon = strchr(rep->sar, ':');
                            if(colon) {
                                int sar_w = atoi(rep->sar);
                                int sar_h = atoi(colon + 1);
                                if(sar_h > 0) par = (double)sar_w / sar_h;
                            }
                        }
                        
                        double display_ar = ((double)width * par) / height;
                        if(fabs(display_ar - 16.0/9.0) < 0.1) {
                            strcpy(rep->displayAspectRatio, "16:9");
                        } else if(fabs(display_ar - 4.0/3.0) < 0.1) {
                            strcpy(rep->displayAspectRatio, "4:3");
                        } else {
                            snprintf(rep->displayAspectRatio, sizeof(rep->displayAspectRatio), "%.2f:1", display_ar);
                        }
                    }
                    
                    // Parse Representation-level SegmentTemplate if present
                    xmlNodePtr rep_temp_node = rep_node->children;
                    while(rep_temp_node != NULL) {
                        if(rep_temp_node->type == XML_ELEMENT_NODE && xmlStrcmp(rep_temp_node->name, (const xmlChar *)"SegmentTemplate") == 0) {
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"initialization");
                            if(prop) { strncpy(rep->segmentTemplate.initialization, (char*)prop, sizeof(rep->segmentTemplate.initialization)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"media");
                            if(prop) { strncpy(rep->segmentTemplate.media, (char*)prop, sizeof(rep->segmentTemplate.media)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"timescale");
                            if(prop) { strncpy(rep->segmentTemplate.timescale, (char*)prop, sizeof(rep->segmentTemplate.timescale)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"startNumber");
                            if(prop) { strncpy(rep->segmentTemplate.startNumber, (char*)prop, sizeof(rep->segmentTemplate.startNumber)-1); xmlFree(prop); }
                            prop = xmlGetProp(rep_temp_node, (const xmlChar *)"duration");
                            if(prop) { strncpy(rep->segmentTemplate.duration, (char*)prop, sizeof(rep->segmentTemplate.duration)-1); xmlFree(prop); }
                            
                            // Parse SegmentTimeline if present
                            xmlNodePtr timeline_node = rep_temp_node->children;
                            SegmentTimelineS* current_s_tail = NULL;
                            while(timeline_node != NULL) {
                                if(timeline_node->type == XML_ELEMENT_NODE && xmlStrcmp(timeline_node->name, (const xmlChar*)"SegmentTimeline") == 0) {
                                    xmlNodePtr s_node = timeline_node->children;
                                    while(s_node != NULL) {
                                        if(s_node->type == XML_ELEMENT_NODE && xmlStrcmp(s_node->name, (const xmlChar*)"S") == 0) {
                                            SegmentTimelineS* s_elem = calloc(1, sizeof(SegmentTimelineS));
                                            if(s_elem) {
                                                prop = xmlGetProp(s_node, (const xmlChar*)"t");
                                                if(prop) { strncpy(s_elem->t, (char*)prop, sizeof(s_elem->t)-1); xmlFree(prop); }
                                                prop = xmlGetProp(s_node, (const xmlChar*)"d");
                                                if(prop) { strncpy(s_elem->d, (char*)prop, sizeof(s_elem->d)-1); xmlFree(prop); }
                                                prop = xmlGetProp(s_node, (const xmlChar*)"r");
                                                if(prop) { strncpy(s_elem->r, (char*)prop, sizeof(s_elem->r)-1); xmlFree(prop); }
                                                
                                                if(rep->segmentTemplate.timeline == NULL) {
                                                    rep->segmentTemplate.timeline = s_elem;
                                                    current_s_tail = s_elem;
                                                } else {
                                                    current_s_tail->next = s_elem;
                                                    current_s_tail = s_elem;
                                                }
                                            }
                                        }
                                        s_node = s_node->next;
                                    }
                                    break;
                                }
                                timeline_node = timeline_node->next;
                            }
                            break;
                        }
                        rep_temp_node = rep_temp_node->next;
                    }

                    // Copy DRM from AdaptationSet to Representation
                    if (adaptationset_drm) {
                        DrmInfo* src_drm = adaptationset_drm;
                        DrmInfo* rep_tail = NULL;
                        
                        while (src_drm) {
                            DrmInfo* copy = calloc(1, sizeof(DrmInfo));
                            if (copy) {
                                strcpy(copy->schemeIdUri, src_drm->schemeIdUri);
                                strcpy(copy->systemName, src_drm->systemName);
                                strcpy(copy->contentId, src_drm->contentId);
                                strcpy(copy->licenseUrl, src_drm->licenseUrl);
                                strcpy(copy->groupLicenseUrl, src_drm->groupLicenseUrl);
                                strcpy(copy->psshData, src_drm->psshData);
                                
                                if (rep->drmInfo == NULL) {
                                    rep->drmInfo = copy;
                                    rep_tail = copy;
                                } else {
                                    rep_tail->next = copy;
                                    rep_tail = copy;
                                }
                            }
                            src_drm = src_drm->next;
                        }
                    }

                    // Add to linked list
                    if (as->head_rep == NULL) {
                        as->head_rep = rep;
                        current_rep_tail = rep;
                    } else {
                        current_rep_tail->next = rep;
                        current_rep_tail = rep;
                    }
                }
                rep_node = rep_node->next;
            }

            // Clean up AdaptationSet DRM
            DrmInfo* cleanup_drm = adaptationset_drm;
            while (cleanup_drm != NULL) {
                DrmInfo* next = cleanup_drm->next;
                free(cleanup_drm);
                cleanup_drm = next;
            }

            // Add AdaptationSet to linked list
            if(mpd_data->head_as == NULL) {
                mpd_data->head_as = as;
                current_as_tail = as;
            } else {
                current_as_tail->next = as;
                current_as_tail = as;
            }
        }
        as_node = as_node->next;
    }
    
    return mpd_data;
}

/**
 * @brief Parses an HELD XML document into HeldData struct.
 */
HeldData* parse_held(xmlDocPtr doc) {
    HeldData* held_data = calloc(1, sizeof(HeldData));
    if (!held_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr cur_node = root->children;

    while(cur_node != NULL) {
        if(cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"HTMLEntryPackage") == 0) {
            xmlChar* prop;
            prop = xmlGetProp(cur_node, (const xmlChar *)"bbandEntryPageUrl");
            if(prop) { strncpy(held_data->bbandEntryPageUrl, (char*)prop, sizeof(held_data->bbandEntryPageUrl)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"clearBbandEntryPageUrl");
            if(prop) { strncpy(held_data->clearBbandEntryPageUrl, (char*)prop, sizeof(held_data->clearBbandEntryPageUrl)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"coupledServices");
            if(prop) { strncpy(held_data->coupledServices, (char*)prop, sizeof(held_data->coupledServices)-1); xmlFree(prop); }
            break; 
        }
        cur_node = cur_node->next;
    }
    return held_data;
}


/**
 * @brief Parses an SLT XML document into SltData struct.
 */
SltData* parse_slt(xmlDocPtr doc) {
    SltData* slt_data = calloc(1, sizeof(SltData));
    if (!slt_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    
    xmlChar* prop = xmlGetProp(root, (const xmlChar *)"bsid");
    if(prop) { strncpy(slt_data->bsid, (char*)prop, sizeof(slt_data->bsid)-1); xmlFree(prop); }

    xmlNodePtr cur_node = root->children;
    ServiceInfo* current_service_tail = NULL;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"Service") == 0) {
            ServiceInfo* service = calloc(1, sizeof(ServiceInfo));
            if (!service) continue;

            prop = xmlGetProp(cur_node, (const xmlChar *)"serviceId");
            if(prop) { strncpy(service->serviceId, (char*)prop, sizeof(service->serviceId)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"majorChannelNo");
            if(prop) { strncpy(service->majorChannelNo, (char*)prop, sizeof(service->majorChannelNo)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"minorChannelNo");
            if(prop) { strncpy(service->minorChannelNo, (char*)prop, sizeof(service->minorChannelNo)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"shortServiceName");
            if(prop) { strncpy(service->shortServiceName, (char*)prop, sizeof(service->shortServiceName)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"globalServiceID");
            if(prop) { strncpy(service->globalServiceID, (char*)prop, sizeof(service->globalServiceID)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"serviceCategory");
            if(prop) { strncpy(service->serviceCategory, (char*)prop, sizeof(service->serviceCategory)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"sltSvcSeqNum");
            if(prop) { strncpy(service->sltSvcSeqNum, (char*)prop, sizeof(service->sltSvcSeqNum)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"protected");
            if(prop) { service->protected = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"broadbandAccessRequired");
            if(prop) { service->broadbandAccessRequired = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"hidden");
            if(prop) { service->hidden = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"hideInGuide");
            if(prop) { service->hideInGuide = (strcmp((char*)prop, "true") == 0 || strcmp((char*)prop, "1") == 0); xmlFree(prop); }


            xmlNodePtr sig_node = cur_node->children;
            while(sig_node != NULL) {
                if(sig_node->type == XML_ELEMENT_NODE && xmlStrcmp(sig_node->name, (const xmlChar*)"BroadcastSvcSignaling") == 0) {
                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsDestinationIpAddress");
                    if(prop) { strncpy(service->slsDestinationIpAddress, (char*)prop, sizeof(service->slsDestinationIpAddress)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsDestinationUdpPort");
                    if(prop) { strncpy(service->slsDestinationUdpPort, (char*)prop, sizeof(service->slsDestinationUdpPort)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsSourceIpAddress");
                    if(prop) { strncpy(service->slsSourceIpAddress, (char*)prop, sizeof(service->slsSourceIpAddress)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsProtocol");
                    if(prop) { strncpy(service->slsProtocol, (char*)prop, sizeof(service->slsProtocol)-1); xmlFree(prop); }
                    
                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsMmtpPacketId");
                    if(prop) { strncpy(service->slsMmtpPacketId, (char*)prop, sizeof(service->slsMmtpPacketId)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsMajorProtocolVersion");
                    if(prop) { strncpy(service->slsMajorProtocolVersion, (char*)prop, sizeof(service->slsMajorProtocolVersion)-1); xmlFree(prop); }

                    prop = xmlGetProp(sig_node, (const xmlChar *)"slsMinorProtocolVersion");
                    if(prop) { strncpy(service->slsMinorProtocolVersion, (char*)prop, sizeof(service->slsMinorProtocolVersion)-1); xmlFree(prop); }

                    break;
                }
                sig_node = sig_node->next;
            }
            
            if (slt_data->head == NULL) {
                slt_data->head = service;
                current_service_tail = service;
            } else {
                current_service_tail->next = service;
                current_service_tail = service;
            }
        }
        cur_node = cur_node->next;
    }
    return slt_data;
}

/**
 * @brief Parses a SystemTime XML document into SystemTimeData struct.
 */
SystemTimeData* parse_system_time(xmlDocPtr doc) {
    // Allocate and zero-out memory for the struct.
    // Using calloc ensures any un-found attributes will be empty strings.
    SystemTimeData* time_data = calloc(1, sizeof(SystemTimeData));
    if (!time_data) {
        // Failed to allocate memory
        return NULL;
    }

    xmlNodePtr root = xmlDocGetRootElement(doc);
    if (!root) {
        free(time_data);
        return NULL;
    }
    
    xmlChar* prop; // Re-usable pointer for attributes

    prop = xmlGetProp(root, (const xmlChar *)"currentUtcOffset");
    if (prop) { strncpy(time_data->currentUtcOffset, (char*)prop, sizeof(time_data->currentUtcOffset)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"ptpPrepend");
    if (prop) { strncpy(time_data->ptpPrepend, (char*)prop, sizeof(time_data->ptpPrepend)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"leap59");
    if (prop) { strncpy(time_data->leap59, (char*)prop, sizeof(time_data->leap59)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"leap61");
    if (prop) { strncpy(time_data->leap61, (char*)prop, sizeof(time_data->leap61)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"utcLocalOffset");
    if (prop) { strncpy(time_data->utcLocalOffset, (char*)prop, sizeof(time_data->utcLocalOffset)-1); xmlFree(prop); }
    
    prop = xmlGetProp(root, (const xmlChar *)"dsStatus");
    if (prop) { strncpy(time_data->dsStatus, (char*)prop, sizeof(time_data->dsStatus)-1); xmlFree(prop); }
    
    prop = xmlGetProp(root, (const xmlChar *)"dsDayOfMonth");
    if (prop) { strncpy(time_data->dsDayOfMonth, (char*)prop, sizeof(time_data->dsDayOfMonth)-1); xmlFree(prop); }

    prop = xmlGetProp(root, (const xmlChar *)"dsHour");
    if (prop) { strncpy(time_data->dsHour, (char*)prop, sizeof(time_data->dsHour)-1); xmlFree(prop); }
    
    return time_data;
}

/**
 * @brief Parses a UCT XML document into UctData struct.
 */
UctData* parse_uct(xmlDocPtr doc) {
    UctData* uct_data = calloc(1, sizeof(UctData));
    if (!uct_data) return NULL;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr ndp_node = root->children;
    NdPackage* current_package_tail = NULL;

    while(ndp_node != NULL && (ndp_node->type != XML_ELEMENT_NODE || xmlStrcmp(ndp_node->name, (const xmlChar *)"NDP") != 0)) {
        ndp_node = ndp_node->next;
    }
    if(ndp_node == NULL) { free(uct_data); return NULL; }

    xmlNodePtr package_node = ndp_node->children;
    while(package_node != NULL) {
        if(package_node->type == XML_ELEMENT_NODE && xmlStrcmp(package_node->name, (const xmlChar *)"NDPackage") == 0) {
            NdPackage* package = calloc(1, sizeof(NdPackage));
            if(!package) continue;

            xmlChar* prop = xmlGetProp(package_node, (const xmlChar*)"name");
            if(prop) { strncpy(package->name, (char*)prop, sizeof(package->name)-1); xmlFree(prop); }

            prop = xmlGetProp(package_node, (const xmlChar*)"dstIP");
            if(prop) { strncpy(package->dstIP, (char*)prop, sizeof(package->dstIP)-1); xmlFree(prop); }
            
            prop = xmlGetProp(package_node, (const xmlChar*)"dstPort");
            if(prop) { strncpy(package->dstPort, (char*)prop, sizeof(package->dstPort)-1); xmlFree(prop); }

            xmlNodePtr element_node = package_node->children;
            NdElement* current_element_tail = NULL;
            while(element_node != NULL) {
                if(element_node->type == XML_ELEMENT_NODE && xmlStrcmp(element_node->name, (const xmlChar*)"NDElement") == 0) {
                     NdElement* element = calloc(1, sizeof(NdElement));
                     if(!element) continue;

                    prop = xmlGetProp(element_node, (const xmlChar*)"name");
                    if(prop) { strncpy(element->name, (char*)prop, sizeof(element->name)-1); xmlFree(prop); }

                    prop = xmlGetProp(element_node, (const xmlChar*)"tsi");
                    if(prop) { strncpy(element->tsi, (char*)prop, sizeof(element->tsi)-1); xmlFree(prop); }

                    if(package->head_element == NULL) {
                        package->head_element = element;
                        current_element_tail = element;
                    } else {
                        current_element_tail->next = element;
                        current_element_tail = element;
                    }
                }
                element_node = element_node->next;
            }

            if (uct_data->head_package == NULL) {
                uct_data->head_package = package;
                current_package_tail = package;
            } else {
                current_package_tail->next = package;
                current_package_tail = package;
            }
        }
        package_node = package_node->next;
    }
    return uct_data;
}

/**
 * @brief Parses a UDST XML document into UdstData struct.
 */
UdstData* parse_udst(xmlDocPtr doc) {
    UdstData* udst_data = calloc(1, sizeof(UdstData));
    if (!udst_data) return NULL;
    
    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlChar* prop = xmlGetProp(root, (const xmlChar*)"version");
    if(prop) { strncpy(udst_data->version, (char*)prop, sizeof(udst_data->version)-1); xmlFree(prop); }

    xmlNodePtr uds_node = root->children;
    while(uds_node != NULL) {
        if(uds_node->type == XML_ELEMENT_NODE && xmlStrcmp(uds_node->name, (const xmlChar*)"UDS") == 0) {
            xmlNodePtr bss_node = uds_node->children;
            while(bss_node != NULL) {
                if(bss_node->type == XML_ELEMENT_NODE && xmlStrcmp(bss_node->name, (const xmlChar*)"broadSpanServices") == 0) {
                    
                    xmlNodePtr service_node = bss_node->children;
                    BroadSpanServiceInfo* current_service_tail = NULL;
                    while(service_node != NULL) {
                        if(service_node->type == XML_ELEMENT_NODE && xmlStrcmp(service_node->name, (const xmlChar*)"broadSpanService") == 0) {
                            BroadSpanServiceInfo* service = calloc(1, sizeof(BroadSpanServiceInfo));
                            if(!service) continue;

                            prop = xmlGetProp(service_node, (const xmlChar*)"name");
                            if(prop) { strncpy(service->name, (char*)prop, sizeof(service->name)-1); xmlFree(prop); }

                            xmlNodePtr rsrv_node = service_node->children;
                            while(rsrv_node != NULL) {
                                if(rsrv_node->type == XML_ELEMENT_NODE && xmlStrcmp(rsrv_node->name, (const xmlChar*)"rsrv") == 0) {
                                    RsrvInfo* rsrv = calloc(1, sizeof(RsrvInfo));
                                    if(rsrv) {
                                        prop = xmlGetProp(rsrv_node, (const xmlChar*)"name");
                                        if(prop) { strncpy(rsrv->name, (char*)prop, sizeof(rsrv->name)-1); xmlFree(prop); }
                                        prop = xmlGetProp(rsrv_node, (const xmlChar*)"srvid");
                                        if(prop) { strncpy(rsrv->srvid, (char*)prop, sizeof(rsrv->srvid)-1); xmlFree(prop); }
                                        prop = xmlGetProp(rsrv_node, (const xmlChar*)"destIP");
                                        if(prop) { strncpy(rsrv->destIP, (char*)prop, sizeof(rsrv->destIP)-1); xmlFree(prop); }
                                        prop = xmlGetProp(rsrv_node, (const xmlChar*)"destPort");
                                        if(prop) { strncpy(rsrv->destPort, (char*)prop, sizeof(rsrv->destPort)-1); xmlFree(prop); }
                                        prop = xmlGetProp(rsrv_node, (const xmlChar*)"orderId");
                                        if(prop) { strncpy(rsrv->orderId, (char*)prop, sizeof(rsrv->orderId)-1); xmlFree(prop); }
                                        service->head_rsrv = rsrv;
                                    }
                                }
                                rsrv_node = rsrv_node->next;
                            }

                             if (udst_data->head_service == NULL) {
                                udst_data->head_service = service;
                                current_service_tail = service;
                            } else {
                                current_service_tail->next = service;
                                current_service_tail = service;
                            }
                        }
                        service_node = service_node->next;
                    }
                }
                bss_node = bss_node->next;
            }
        }
        uds_node = uds_node->next;
    }
    return udst_data;
}

/**
 * @brief Parses a BundleDescriptionROUTE (User Service Description) XML document.
 */
UserServiceDescriptionData* parse_user_service_description(xmlDocPtr doc) {
    UserServiceDescriptionData* usd_data = calloc(1, sizeof(UserServiceDescriptionData));
    if (!usd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr cur_node = root->children;
    UsdEntry* current_entry_tail = NULL;
    xmlChar* prop;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"item") == 0) {
            UsdEntry* entry = calloc(1, sizeof(UsdEntry));
            if (!entry) continue;

            prop = xmlGetProp(cur_node, (const xmlChar *)"contentType");
            if(prop) { strncpy(entry->contentType, (char*)prop, sizeof(entry->contentType)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"version");
            if(prop) { strncpy(entry->version, (char*)prop, sizeof(entry->version)-1); xmlFree(prop); }
            
            prop = xmlGetProp(cur_node, (const xmlChar *)"userAgent");
            if(prop) { strncpy(entry->userAgent, (char*)prop, sizeof(entry->userAgent)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"filterCodes");
            if(prop) { strncpy(entry->filterCodes, (char*)prop, sizeof(entry->filterCodes)-1); xmlFree(prop); }
            
            if (usd_data->head == NULL) {
                usd_data->head = entry;
                current_entry_tail = entry;
            } else {
                current_entry_tail->next = entry;
                current_entry_tail = entry;
            }
        }
        cur_node = cur_node->next;
    }

    return usd_data;
}

char* extract_node_as_xml(xmlNodePtr node) {
    if (!node) return NULL;
    
    xmlBufferPtr buf = xmlBufferCreate();
    if (!buf) return NULL;
    
    // Create a complete XML document with declaration
    xmlBufferAdd(buf, (const xmlChar*)"<?xml version=\"1.0\" encoding=\"UTF-8\"?>", -1);
    xmlNodeDump(buf, node->doc, node, 0, 1);
    
    char* result = strdup((char*)buf->content);
    xmlBufferFree(buf);
    
    return result;
}

/**
 * @brief NEW: Parses a BundleDescriptionMMT XML document.
 */
UsdbData* parse_usbd(xmlDocPtr doc) {
    UsdbData* usbd_data = calloc(1, sizeof(UsdbData));
    if (!usbd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr cur_node = root->children;
    UsdEntryMmt* entry_tail = NULL;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && 
            xmlStrcmp(cur_node->name, (const xmlChar *)"UserServiceDescription") == 0) {
            
            // Found a USD - parse it and also store it as a separate table
            char* usd_xml = extract_node_as_xml(cur_node);
            if (usd_xml) {
                TableType type = TABLE_TYPE_USD;
                void* usd_parsed_data = NULL;
                if (parse_xml(usd_xml, strlen(usd_xml), &type, &usd_parsed_data, "Nested USD") == 0 && usd_parsed_data) {
                    store_unique_table(usd_xml, strlen(usd_xml), TABLE_TYPE_USD, usd_parsed_data, "", "");
                }
                free(usd_xml);
            }
            
            // Also store basic info in USBD structure
            UsdEntryMmt* entry = calloc(1, sizeof(UsdEntryMmt));
            if (entry) {
                xmlChar* prop = xmlGetProp(cur_node, (const xmlChar *)"serviceId");
                if(prop) { strncpy(entry->id, (char*)prop, sizeof(entry->id)-1); xmlFree(prop); }
                
                strcpy(entry->contentType, "UserServiceDescription");
                strcpy(entry->version, "1.0");
                
                if (usbd_data->head == NULL) {
                    usbd_data->head = entry;
                    entry_tail = entry;
                } else {
                    entry_tail->next = entry;
                    entry_tail = entry;
                }
            }
        }
        cur_node = cur_node->next;
    }

    return usbd_data;
}

UsdData* parse_usd(xmlDocPtr doc) {
    UsdData* usd_data = calloc(1, sizeof(UsdData));
    if (!usd_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlChar* prop;
    
    // Parse USD attributes
    prop = xmlGetProp(root, (const xmlChar *)"serviceId");
    if(prop) { strncpy(usd_data->serviceId, (char*)prop, sizeof(usd_data->serviceId)-1); xmlFree(prop); }

    xmlNodePtr cur_node = root->children;
    
    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE) {
            if (xmlStrcmp(cur_node->name, (const xmlChar *)"Name") == 0) {
                xmlChar* content = xmlNodeGetContent(cur_node);
                if(content) {
                    strncpy(usd_data->serviceName, (char*)content, sizeof(usd_data->serviceName)-1);
                    xmlFree(content);
                }
            } else if (xmlStrcmp(cur_node->name, (const xmlChar *)"MPUComponent") == 0) {
                prop = xmlGetProp(cur_node, (const xmlChar *)"mmtPackageId");
                if(prop) { 
                    strncpy(usd_data->mmtPackageId, (char*)prop, sizeof(usd_data->mmtPackageId)-1); 
                    xmlFree(prop); 
                }
            } else if (xmlStrcmp(cur_node->name, (const xmlChar *)"ComponentInfo") == 0) {
                UsdComponent* component = calloc(1, sizeof(UsdComponent));
                if (component) {
                    prop = xmlGetProp(cur_node, (const xmlChar *)"componentId");
                    if(prop) { 
                        strncpy(component->componentId, (char*)prop, sizeof(component->componentId)-1); 
                        xmlFree(prop); 
                    }
                    
                    prop = xmlGetProp(cur_node, (const xmlChar *)"componentType");
                    if(prop) { 
                        component->componentType = atoi((char*)prop);
                        xmlFree(prop); 
                    }
                    
                    prop = xmlGetProp(cur_node, (const xmlChar *)"componentRole");
                    if(prop) { 
                        component->componentRole = atoi((char*)prop);
                        xmlFree(prop); 
                    }
                    
                    // Generate description
                    const char* type_str = (component->componentType == 0) ? "Audio" :
                                          (component->componentType == 1) ? "Video" :
                                          (component->componentType == 2) ? "Data/Captions" : "Unknown";
                    const char* role_str = (component->componentRole == 0) ? "Main" : "Alternate";
                    snprintf(component->description, sizeof(component->description), 
                            "%s %s", role_str, type_str);
                    
                    // Add to component list
                    if (usd_data->components == NULL) {
                        usd_data->components = component;
                    } else {
                        UsdComponent* tail = usd_data->components;
                        while (tail->next) tail = tail->next;
                        tail->next = component;
                    }
                }
            }
        }
        cur_node = cur_node->next;
    }

    return usd_data;
}

MptMessageData* parse_mpt_message(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    if (size < 10) return NULL;
    
    MptMessageData* mpt = calloc(1, sizeof(MptMessageData));
    if (!mpt) return NULL;
    
    const uint8_t* pos = buffer;
    size_t remaining = size;
    
    // Table ID (should be 0x20 for MPT)
    mpt->table_id = *pos++;
    remaining--;
    
    // Version
    mpt->version = *pos++;
    remaining--;
    
    // Length (2 bytes)
    if (remaining < 2) goto error;
    mpt->length = ntohs(*(uint16_t*)pos);
    pos += 2;
    remaining -= 2;
    
    // MMT Package ID length (1 byte)
    if (remaining < 1) goto error;
    mpt->mmt_package_id_length = *pos++;
    remaining--;
    
    // MMT Package ID (variable length)
    if (remaining < mpt->mmt_package_id_length) goto error;
    if (mpt->mmt_package_id_length < sizeof(mpt->mmt_package_id)) {
        memcpy(mpt->mmt_package_id, pos, mpt->mmt_package_id_length);
        mpt->mmt_package_id[mpt->mmt_package_id_length] = '\0';
    }
    pos += mpt->mmt_package_id_length;
    remaining -= mpt->mmt_package_id_length;
    
    // MPT mode (1 byte)
    if (remaining < 1) goto error;
    mpt->mpt_mode = *pos++;
    remaining--;
    
    // MMT_general_location_info (skip for now if present)
    if (mpt->mpt_mode == 0x01) {
        if (remaining < 1) goto error;
        uint8_t location_info_length = *pos++;
        remaining--;
        if (remaining < location_info_length) goto error;
        pos += location_info_length;
        remaining -= location_info_length;
    }
    
    // MPU_timestamp_descriptor (1 byte)
    if (remaining < 1) goto error;
    mpt->mpu_timestamp_descriptor = *pos++;
    remaining--;
    
    // Number of assets (1 byte)
    if (remaining < 1) goto error;
    mpt->num_of_assets = *pos++;
    remaining--;
    
    // Parse each asset
    MptAssetInfo* asset_tail = NULL;
    for (int i = 0; i < mpt->num_of_assets; i++) {
        if (remaining < 1) goto error;
        
        MptAssetInfo* asset = calloc(1, sizeof(MptAssetInfo));
        if (!asset) goto error;
        
        // Asset ID length
        asset->asset_id_length = *pos++;
        remaining--;
        
        // Asset ID
        if (remaining < asset->asset_id_length) {
            free(asset);
            goto error;
        }
        if (asset->asset_id_length < sizeof(asset->asset_id)) {
            memcpy(asset->asset_id, pos, asset->asset_id_length);
            asset->asset_id[asset->asset_id_length] = '\0';
        }
        pos += asset->asset_id_length;
        remaining -= asset->asset_id_length;
        
        // Asset type length
        if (remaining < 1) {
            free(asset);
            goto error;
        }
        asset->asset_type_length = *pos++;
        remaining--;
        
        // Asset type
        if (remaining < asset->asset_type_length) {
            free(asset);
            goto error;
        }
        if (asset->asset_type_length < sizeof(asset->asset_type)) {
            memcpy(asset->asset_type, pos, asset->asset_type_length);
            asset->asset_type[asset->asset_type_length] = '\0';
        }
        pos += asset->asset_type_length;
        remaining -= asset->asset_type_length;
        
        // Asset clock relation flag + reserved
        if (remaining < 1) {
            free(asset);
            goto error;
        }
        asset->asset_clock_relation_flag = (*pos >> 7) & 0x1;
        pos++;
        remaining--;
        
        // Location count
        if (remaining < 1) {
            free(asset);
            goto error;
        }
        asset->location_count = *pos++;
        remaining--;
        
        // Parse locations
        MptAssetLocation* loc_tail = NULL;
        for (int j = 0; j < asset->location_count; j++) {
            if (remaining < 1) {
                free(asset);
                goto error;
            }
            
            MptAssetLocation* loc = calloc(1, sizeof(MptAssetLocation));
            if (!loc) {
                free(asset);
                goto error;
            }
            
            // Location type
            loc->location_type = *pos++;
            remaining--;
            
            if (loc->location_type == 0x00) {
                // Packet-based location
                if (remaining < 2) {
                    free(loc);
                    free(asset);
                    goto error;
                }
                loc->packet_id = ntohs(*(uint16_t*)pos);
                pos += 2;
                remaining -= 2;
                
            } else if (loc->location_type == 0x01) {
                // URL-based location - skip for now
                if (remaining < 1) {
                    free(loc);
                    free(asset);
                    goto error;
                }
                uint8_t url_length = *pos++;
                remaining--;
                if (remaining < url_length) {
                    free(loc);
                    free(asset);
                    goto error;
                }
                pos += url_length;
                remaining -= url_length;
            }
            
            // Add location to list
            if (!asset->locations) {
                asset->locations = loc;
                loc_tail = loc;
            } else {
                loc_tail->next = loc;
                loc_tail = loc;
            }
        }
        
        // Descriptor count for this asset
        if (remaining < 1) {
            free(asset);
            goto error;
        }
        asset->descriptor_count = *pos++;
        remaining--;
        
        // Parse asset descriptors (if any)
        MptAssetDescriptor* desc_tail = NULL;
        for (int j = 0; j < asset->descriptor_count; j++) {
            if (remaining < 2) {
                free(asset);
                goto error;
            }
            
            MptAssetDescriptor* desc = calloc(1, sizeof(MptAssetDescriptor));
            if (!desc) {
                free(asset);
                goto error;
            }
            
            desc->descriptor_tag = *pos++;
            desc->descriptor_length = *pos++;
            remaining -= 2;
            
            if (remaining < desc->descriptor_length) {
                free(desc);
                free(asset);
                goto error;
            }
            
            desc->descriptor_data = malloc(desc->descriptor_length);
            if (desc->descriptor_data) {
                memcpy(desc->descriptor_data, pos, desc->descriptor_length);
            }
            pos += desc->descriptor_length;
            remaining -= desc->descriptor_length;
            
            // Add descriptor to list
            if (!asset->descriptors) {
                asset->descriptors = desc;
                desc_tail = desc;
            } else {
                desc_tail->next = desc;
                desc_tail = desc;
            }
        }
        
        // Add asset to MPT
        if (!mpt->assets) {
            mpt->assets = asset;
            asset_tail = asset;
        } else {
            asset_tail->next = asset;
            asset_tail = asset;
        }
    }
    
    return mpt;
    
error:
    printf("ERROR: MPT parsing failed\n");
    free_mpt_message_data(mpt);
    return NULL;
}

// Free function
void free_mpt_message_data(MptMessageData* mpt) {
    if (!mpt) return;
    
    MptAssetInfo* asset = mpt->assets;
    while (asset) {
        MptAssetInfo* next_asset = asset->next;
        
        // Free locations
        MptAssetLocation* loc = asset->locations;
        while (loc) {
            MptAssetLocation* next_loc = loc->next;
            free(loc);
            loc = next_loc;
        }
        
        // Free descriptors
        MptAssetDescriptor* desc = asset->descriptors;
        while (desc) {
            MptAssetDescriptor* next_desc = desc->next;
            free(desc->descriptor_data);
            free(desc);
            desc = next_desc;
        }
        
        free(asset);
        asset = next_asset;
    }
    
    free(mpt);
}

/**
 * @brief NEW: Parses a DWD (placeholder).
 */
DwdData* parse_dwd(xmlDocPtr doc) {
    DwdData* dwd_data = calloc(1, sizeof(DwdData));
    if (!dwd_data) return NULL;
    strncpy(dwd_data->placeholder, "Parsed", sizeof(dwd_data->placeholder)-1);
    return dwd_data;
}


/**
 * @brief Parses a metadataEnvelope (Service Signaling) XML document.
 */
ServiceSignalingData* parse_service_signaling(xmlDocPtr doc) {
    ServiceSignalingData* signaling_data = calloc(1, sizeof(ServiceSignalingData));
    if (!signaling_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr cur_node = root->children;
    ServiceSignalingFragment* current_frag_tail = NULL;
    xmlChar* prop;

    while (cur_node != NULL) {
        if (cur_node->type == XML_ELEMENT_NODE && xmlStrcmp(cur_node->name, (const xmlChar *)"metadataFragment") == 0) {
            ServiceSignalingFragment* frag = calloc(1, sizeof(ServiceSignalingFragment));
            if (!frag) continue;

            prop = xmlGetProp(cur_node, (const xmlChar *)"contentType");
            if(prop) { strncpy(frag->contentType, (char*)prop, sizeof(frag->contentType)-1); xmlFree(prop); }

            prop = xmlGetProp(cur_node, (const xmlChar *)"version");
            if(prop) { strncpy(frag->version, (char*)prop, sizeof(frag->version)-1); xmlFree(prop); }
            
            if (signaling_data->head == NULL) {
                signaling_data->head = frag;
                current_frag_tail = frag;
            } else {
                current_frag_tail->next = frag;
                current_frag_tail = frag;
            }
        }
        cur_node = cur_node->next;
    }

    return signaling_data;
}

/**
 * @brief Parses an S-TSID XML document into an StsidData struct.
 * Also triggers parsing of embedded FDT-Instances.
 */
StsidData* parse_stsid(xmlDocPtr doc) {
    StsidData* stsid_data = calloc(1, sizeof(StsidData));
    if (!stsid_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlNodePtr rs_node = root->children;
    StsidLogicalStream* current_ls_tail = NULL;
    xmlChar* prop;

    // Find the RS node
    while (rs_node != NULL && (rs_node->type != XML_ELEMENT_NODE || xmlStrcmp(rs_node->name, (const xmlChar *)"RS") != 0)) {
        rs_node = rs_node->next;
    }
    if (!rs_node) {
        free(stsid_data);
        return NULL;
    }

    prop = xmlGetProp(rs_node, (const xmlChar*)"dIpAddr");
    if(prop) { strncpy(stsid_data->dIpAddr, (char*)prop, sizeof(stsid_data->dIpAddr)-1); xmlFree(prop); }
    prop = xmlGetProp(rs_node, (const xmlChar*)"dPort");
    if(prop) { strncpy(stsid_data->dPort, (char*)prop, sizeof(stsid_data->dPort)-1); xmlFree(prop); }

    // Iterate through LS nodes
    xmlNodePtr ls_node = rs_node->children;
    int ls_count = 0;
    while(ls_node != NULL) {
        if(ls_node->type == XML_ELEMENT_NODE && xmlStrcmp(ls_node->name, (const xmlChar *)"LS") == 0) {
            StsidLogicalStream* ls = calloc(1, sizeof(StsidLogicalStream));
            if(!ls) continue;

            prop = xmlGetProp(ls_node, (const xmlChar*)"tsi");
            if(prop) { 
                strncpy(ls->tsi, (char*)prop, sizeof(ls->tsi)-1); 
                xmlFree(prop); 
            }

            // MOVE THE LINKED LIST ADDITION HERE, BEFORE MediaInfo parsing
            if (stsid_data->head_ls == NULL) {
                stsid_data->head_ls = ls;
                current_ls_tail = ls;
            } else {
                current_ls_tail->next = ls;
                current_ls_tail = ls;
            }
            ls_count++;

            // Now try to find MediaInfo (this might fail, but stream is already added)
            xmlNodePtr srcflow_node = ls_node->children;
            while(srcflow_node != NULL && (srcflow_node->type != XML_ELEMENT_NODE || xmlStrcmp(srcflow_node->name, (const xmlChar*)"SrcFlow") != 0)) {
                srcflow_node = srcflow_node->next;
            }
            if(srcflow_node) {
                xmlNodePtr contentinfo_node = srcflow_node->children;
                 while(contentinfo_node != NULL && (contentinfo_node->type != XML_ELEMENT_NODE || xmlStrcmp(contentinfo_node->name, (const xmlChar*)"ContentInfo") != 0)) {
                    contentinfo_node = contentinfo_node->next;
                }
                if(contentinfo_node) {
                    xmlNodePtr mediainfo_node = contentinfo_node->children;
                     while(mediainfo_node != NULL && (mediainfo_node->type != XML_ELEMENT_NODE || xmlStrcmp(mediainfo_node->name, (const xmlChar*)"MediaInfo") != 0)) {
                        mediainfo_node = mediainfo_node->next;
                    }
                    if(mediainfo_node) {
                        prop = xmlGetProp(mediainfo_node, (const xmlChar*)"repId");
                        if(prop) { 
                            strncpy(ls->repId, (char*)prop, sizeof(ls->repId)-1); 
                            xmlFree(prop); 
                        }
                        prop = xmlGetProp(mediainfo_node, (const xmlChar*)"contentType");
                        if(prop) { 
                            strncpy(ls->contentType, (char*)prop, sizeof(ls->contentType)-1); 
                            xmlFree(prop); 
                        }
                        
                        // Parse ContentRatings
                        xmlNodePtr rating_node = mediainfo_node->children;
                        ContentRatingInfo* current_rating_tail = NULL;
                        while(rating_node != NULL) {
                            if(rating_node->type == XML_ELEMENT_NODE && xmlStrcmp(rating_node->name, (const xmlChar*)"ContentRating") == 0) {
                                ContentRatingInfo* rating = calloc(1, sizeof(ContentRatingInfo));
                                if(rating) {
                                    prop = xmlGetProp(rating_node, (const xmlChar*)"value");
                                    if(prop) { strncpy(rating->value, (char*)prop, sizeof(rating->value)-1); xmlFree(prop); }
                                    
                                    if(ls->head_rating == NULL) {
                                        ls->head_rating = rating;
                                        current_rating_tail = rating;
                                    } else {
                                        current_rating_tail->next = rating;
                                        current_rating_tail = rating;
                                    }
                                }
                            }
                            rating_node = rating_node->next;
                        }
                    }
                }
                // Also parse any embedded tables like FDT within the SrcFlow
                parse_embedded_children(srcflow_node, stsid_data->dIpAddr, stsid_data->dPort);
            }
        }
        ls_node = ls_node->next;
    }
    return stsid_data;
}

/**
 * @brief Parses an MMT MP_Table XML document.
 */
MpTableData* parse_mp_table(xmlDocPtr doc) {
    MpTableData* mpt_data = calloc(1, sizeof(MpTableData));
    if (!mpt_data) return NULL;

    xmlNodePtr root = xmlDocGetRootElement(doc);
    xmlChar* prop = xmlGetProp(root, (const xmlChar *)"MPTpackageID");
    if(prop) { strncpy(mpt_data->mptPackageId, (char*)prop, sizeof(mpt_data->mptPackageId)-1); xmlFree(prop); }

    xmlNodePtr asset_node = root->children;
    MptAsset* current_asset_tail = NULL;
    
    while (asset_node != NULL) {
        if (asset_node->type == XML_ELEMENT_NODE && xmlStrcmp(asset_node->name, (const xmlChar *)"Asset") == 0) {
            MptAsset* asset = calloc(1, sizeof(MptAsset));
            if(!asset) continue;

            prop = xmlGetProp(asset_node, (const xmlChar*)"assetId");
            if(prop) { strncpy(asset->assetId, (char*)prop, sizeof(asset->assetId)-1); xmlFree(prop); }
            prop = xmlGetProp(asset_node, (const xmlChar*)"assetType");
            if(prop) { strncpy(asset->assetType, (char*)prop, sizeof(asset->assetType)-1); xmlFree(prop); }
            
            // Find the packetId in the location info
            xmlNodePtr location_node = asset_node->children;
            while(location_node != NULL && (location_node->type != XML_ELEMENT_NODE || xmlStrcmp(location_node->name, (const xmlChar*)"MPT_Location_Info") != 0)) {
                location_node = location_node->next;
            }
            if(location_node) {
                prop = xmlGetProp(location_node, (const xmlChar*)"packetId");
                if(prop) { strncpy(asset->packetId, (char*)prop, sizeof(asset->packetId)-1); xmlFree(prop); }
            }

            if(mpt_data->head_asset == NULL) {
                mpt_data->head_asset = asset;
                current_asset_tail = asset;
            } else {
                current_asset_tail->next = asset;
                current_asset_tail = asset;
            }
        }
        asset_node = asset_node->next;
    }

    return mpt_data;
}

/**
 * @brief Enhanced GZIP decompression with better error reporting
 */
char* decompress_gzip(const uint8_t* compressed_data, int compressed_size, int* decompressed_size_out, int* consumed_size_out) {
    *decompressed_size_out = 0;
    *consumed_size_out = 0;

    if (compressed_size < 10) {
        printf("DEBUG GZIP: Input too small (%d bytes)\n", compressed_size);
        return NULL;
    }

    // Verify GZIP header
    if (compressed_data[0] != 0x1f || compressed_data[1] != 0x8b) {
        printf("DEBUG GZIP: Invalid magic bytes: %02x %02x\n", compressed_data[0], compressed_data[1]);
        return NULL;
    }

    z_stream stream = {0};
    if (inflateInit2(&stream, 16 + MAX_WBITS) != Z_OK) {
        printf("DEBUG GZIP: inflateInit2 failed\n");
        return NULL;
    }

    // Start with 64KB output buffer, expand if needed
    int output_buffer_size = 65536;
    char* output_buffer = malloc(output_buffer_size);
    if (!output_buffer) {
        inflateEnd(&stream);
        return NULL;
    }

    stream.next_in = (Bytef*)compressed_data;
    stream.avail_in = compressed_size;
    stream.next_out = (Bytef*)output_buffer;
    stream.avail_out = output_buffer_size;
    
    int ret;

    do {
        ret = inflate(&stream, Z_NO_FLUSH);

        if (ret == Z_STREAM_ERROR || ret == Z_MEM_ERROR) {
            free(output_buffer);
            inflateEnd(&stream);
            return NULL;
        }

        // For Z_DATA_ERROR, if we got significant output, use it anyway
        if (ret == Z_DATA_ERROR) {
            if (stream.total_out > 100) {  // We got at least some useful data
                *decompressed_size_out = stream.total_out;
                *consumed_size_out = compressed_size - stream.avail_in;
                inflateEnd(&stream);
                if (*decompressed_size_out < output_buffer_size) {
                    output_buffer[*decompressed_size_out] = '\0';
                }
                return output_buffer;
            }
            free(output_buffer);
            inflateEnd(&stream);
            return NULL;
        }

        // If output buffer is full, expand it
        if (stream.avail_out == 0 && ret != Z_STREAM_END) {
            int current_size = output_buffer_size - stream.avail_out;
            output_buffer_size *= 2;
            char* new_buffer = realloc(output_buffer, output_buffer_size);
            if (!new_buffer) {
                free(output_buffer);
                inflateEnd(&stream);
                return NULL;
            }
            output_buffer = new_buffer;
            stream.next_out = (Bytef*)(output_buffer + current_size);
            stream.avail_out = output_buffer_size - current_size;
        }

    } while (ret != Z_STREAM_END && stream.avail_in > 0);

    *decompressed_size_out = stream.total_out;
    *consumed_size_out = compressed_size - stream.avail_in;

    inflateEnd(&stream);

    // Null-terminate for safety when treating as string
    if (*decompressed_size_out < output_buffer_size) {
        output_buffer[*decompressed_size_out] = '\0';
    }

    return output_buffer;
}

/**
 * @brief Enhanced MMT packet header parser based on libatsc3 logic
 */
int parse_mmt_packet_header(const uint8_t* buffer, size_t length, mmt_packet_header_t* header) {
    if (!buffer || !header || length < 4) {
        return -1;
    }
    
    memset(header, 0, sizeof(mmt_packet_header_t));
    
    const uint8_t* pos = buffer;
    size_t remaining = length;
    
    // Parse fixed header (4 bytes minimum)
    if (remaining < 4) return -1;
    
    header->version = (pos[0] >> 6) & 0x3;
    header->packet_counter_flag = (pos[0] >> 5) & 0x1;
    header->fec_type = (pos[0] >> 4) & 0x1;
    header->extension_flag = (pos[0] >> 3) & 0x1;
    header->rap_flag = (pos[0] >> 2) & 0x1;
    // bits 1-0 are reserved
    
    header->packet_id = ntohs(*(uint16_t*)(pos + 2));
    
    pos += 4;
    remaining -= 4;
    
    // Parse timestamp (4 bytes)
    if (remaining < 4) return -1;
    header->timestamp = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    // Parse packet sequence number (4 bytes)
    if (remaining < 4) return -1;
    header->packet_sequence_number = ntohl(*(uint32_t*)pos);
    pos += 4;
    remaining -= 4;
    
    // Parse packet counter if present
    if (header->packet_counter_flag) {
        if (remaining < 2) return -1;
        header->packet_counter = ntohs(*(uint16_t*)pos);
        pos += 2;
        remaining -= 2;
    }
    
    // Parse header extension if present
    if (header->extension_flag) {
        if (remaining < 4) return -1;
        header->extension_type = ntohs(*(uint16_t*)pos);
        header->extension_length = ntohs(*(uint16_t*)(pos + 2));
        pos += 4;
        remaining -= 4;
        
        if (remaining < header->extension_length) return -1;
        if (header->extension_length > 0) {
            header->extension_data = malloc(header->extension_length);
            if (header->extension_data) {
                memcpy(header->extension_data, pos, header->extension_length);
            }
        }
        pos += header->extension_length;
        remaining -= header->extension_length;
    }
    
    // Calculate payload offset and length
    header->payload_length = remaining;
    
    
    return pos - buffer; // Return header length
}

/**
 * @brief Parse MMT signaling message
 */
int parse_mmt_signaling_message(const uint8_t* buffer, size_t length, mmt_signaling_message_t* message) {
    if (!buffer || !message || length < 7) {
        return -1;
    }
    
    memset(message, 0, sizeof(mmt_signaling_message_t));
    
    const uint8_t* pos = buffer;
    
    // Parse message header
    message->message_id = ntohs(*(uint16_t*)pos);
    pos += 2;
    
    message->version = *pos++;
    
    message->length = ntohl(*(uint32_t*)pos) & 0xFFFFFF; // 24-bit length
    pos += 3;
    
    if (length < 7 + message->length) {
        return -1;
    }
    
    // Copy payload
    if (message->length > 0) {
        message->payload = malloc(message->length);
        if (message->payload) {
            memcpy(message->payload, pos, message->length);
        } else {
            return -1;
        }
    }
    
    
    return 7 + message->length;
}

/**
 * @brief Process MMT signaling message and extract useful information
 */
void process_mmt_signaling_message(mmt_signaling_message_t* message, const char* destIp, const char* destPort) {
    if (!message || !message->payload) return;
    
    switch (message->message_id) {
        case MMT_SIGNALING_MPT_MESSAGE: 
            MptMessageData* mpt_data = parse_mpt_message(message->payload, message->length, destIp, destPort);
            if (mpt_data) {
                // Store it
                char content_id[256];
                snprintf(content_id, sizeof(content_id), "MMT_MPT_Structured_%s:%s", destIp, destPort);
                store_unique_table(content_id, strlen(content_id), TABLE_TYPE_MP_TABLE_BINARY, 
                                 mpt_data, destIp, destPort);
            }
            break;
        
        case MMT_SIGNALING_PA_MESSAGE:
            break;
            
        case MMT_SIGNALING_MPI_MESSAGE: {
            break;
        }
            
        default:
            break;
    }
}

ProprietaryMptData* parse_proprietary_mpt(const uint8_t* buffer, size_t size) {
    if (size < 30) return NULL;
    
    const uint8_t* pos = buffer;
    
    
    ProprietaryMptData* mpt = calloc(1, sizeof(ProprietaryMptData));
    if (!mpt) return NULL;
    
    // MPT Message Header
    mpt->table_id = *pos++;
    mpt->version = *pos++;
    mpt->length = ntohs(*(uint16_t*)pos);
    pos += 2;
    
    if (mpt->table_id != 0x20) {
        free(mpt);
        return NULL;
    }
    
    // Package-level descriptor
    if (*pos == 0xfe) {
        uint8_t desc_len = *pos++;
        
        if (desc_len < sizeof(mpt->package_descriptor)) {
            memcpy(mpt->package_descriptor, pos, desc_len);
            mpt->package_descriptor[desc_len] = '\0';
        }
        pos += desc_len;
    }
    
    // Skip mystery bytes (00 00 04 00 00 00 00 01)
    if (pos[0] == 0x00 && pos[1] == 0x00 && pos[2] == 0x04) {
        pos += 8;
    }
    
    // Parse assets
    ProprietaryMptAsset* asset_tail = NULL;
    int asset_count = 0;
    
    while (pos < buffer + size - 30) {
        
        // Asset starts with 00 00 00 XX where XX is length
        if (pos[0] != 0x00 || pos[1] != 0x00 || pos[2] != 0x00) {
            break;
        }
        
        ProprietaryMptAsset* asset = calloc(1, sizeof(ProprietaryMptAsset));
        if (!asset) break;
        
        // Asset ID length
        pos += 3;
        asset->asset_id_length = *pos++;
        
        if (asset->asset_id_length == 0 || asset->asset_id_length >= sizeof(asset->asset_id) || 
            pos + asset->asset_id_length > buffer + size) {
            free(asset);
            break;
        }
        
        // Asset ID string
        memcpy(asset->asset_id, pos, asset->asset_id_length);
        asset->asset_id[asset->asset_id_length] = '\0';
        pos += asset->asset_id_length;
        
        // NEW: Parse asset type/codec field (4 bytes)
        if (pos + 4 <= buffer + size) {
            char type_field[5];
            memcpy(type_field, pos, 4);
            type_field[4] = '\0';
            
            // This is the codec identifier
            strncpy(asset->codec, type_field, sizeof(asset->codec) - 1);
            
            // Determine asset type from codec
            if (strcmp(type_field, "hvc1") == 0 || strcmp(type_field, "hev1") == 0) {
                strcpy(asset->asset_type, "Video");
            } else if (strncmp(type_field, "ac-4", 4) == 0) {
                strcpy(asset->asset_type, "Audio");
            } else if (strcmp(type_field, "stpp") == 0) {
                strcpy(asset->asset_type, "Captions");
            } else if (strcmp(type_field, "mp4a") == 0) {
                strcpy(asset->asset_type, "Audio");
            } else {
                strcpy(asset->asset_type, "Unknown");
            }
            pos += 4;
        } else {
            free(asset);
            break;
        }
        
        // Next should be FE descriptor with packet ID
        
        if (*pos != 0xfe) {
            free(asset);
            break;
        }
        
        pos++; // skip FE
        uint8_t desc_len = *pos++;

        // Skip the descriptor payload
        if (pos + desc_len > buffer + size) {
            printf("    ERROR: Descriptor extends beyond buffer\n");
            free(asset);
            break;
        }
        pos += desc_len;

        // Packet ID comes AFTER the descriptor (2 bytes, big-endian)
        if (pos + 2 > buffer + size) {
            printf("    ERROR: Not enough bytes for packet ID\n");
            free(asset);
            break;
        }

        asset->packet_id = ntohs(*(uint16_t*)pos);
        pos += 2;

        // Check if there are more assets coming (look ahead for the 00 00 00 XX pattern)
        if (pos + 7 <= buffer + size && pos + 7 + 4 <= buffer + size) {
            // Check if next bytes look like another asset header
            if (pos[7] == 0x00 && pos[8] == 0x00 && pos[9] == 0x00) {
                pos += 7;
            }
        }

        // ONLY add to list after all validation passed
        if (!mpt->assets) {
            mpt->assets = asset;
            asset_tail = asset;
        } else {
            asset_tail->next = asset;
            asset_tail = asset;
        }
        asset_count++;
    }
    
    mpt->num_assets = asset_count;
    
    return mpt;
}

void free_proprietary_mpt_data(ProprietaryMptData* mpt) {
    if (!mpt) {
        return;
    }
    
    ProprietaryMptAsset* asset = mpt->assets;
    int freed_count = 0;
    
    while (asset) {
        
        // Check if the pointer looks valid (not obviously corrupted)
        if ((uintptr_t)asset < 0x1000) {
            break;
        }
        
        ProprietaryMptAsset* next = asset->next;
        
        free(asset);
        asset = next;
        freed_count++;
        
        // Safety check - if we've freed more than expected, something is wrong
        if (freed_count > 100) {
            break;
        }
    }
    free(mpt);
}

// Parse MPU header
int parse_mpu_header(const uint8_t* buffer, size_t length, MpuHeader* header) {
    if (!buffer || !header || length < 8) return -1;
    
    const uint8_t* pos = buffer;
    
    header->mpu_sequence_number = ntohl(*(uint32_t*)pos);
    pos += 4;
    
    header->fragmentation_indicator = (pos[0] >> 6) & 0x3;
    header->fragment_type = pos[0] & 0x7;
    pos += 4;
    
    header->mfu_data = pos;
    header->mfu_data_length = length - (pos - buffer);
    
    return pos - buffer;
}

// Extract HEVC parameters - NO FALLBACKS
void extract_hevc_params(const uint8_t* data, size_t len, MmtMediaParams* params) {
    // Start loop at i=4 to safely access data[i-4]
    for (size_t i = 4; i < len - 32; i++) {
        if ((data[i-3] == 0 && data[i-2] == 0 && data[i-1] == 1) ||
            (data[i-4] == 0 && data[i-3] == 0 && data[i-2] == 0 && data[i-1] == 1)) {
            
            uint8_t nal_type = (data[i] >> 1) & 0x3F;
            
            if (nal_type == 33 && i + 20 < len) { // SPS
                strcpy(params->video_codec, "HEVC");
                
                uint16_t width_hint = (data[i+7] << 8) | data[i+8];
                
                if (width_hint > 0x700 && width_hint < 0x800) {
                    strcpy(params->resolution, "1920x1080");
                    strcpy(params->scan_type, "progressive");
                    strcpy(params->frame_rate, "59.94");
                } else if (width_hint > 0x400 && width_hint < 0x600) {
                    strcpy(params->resolution, "1280x720");
                    strcpy(params->scan_type, "progressive");
                    strcpy(params->frame_rate, "59.94");
                }
                return;
            }
        }
    }
}

void extract_ac4_params(const uint8_t* data, size_t len, MmtMediaParams* params) {
    // Need at least 12 bytes to safely check for 'dac4' and access config
    if (len < 12) {
        return;
    }
    
    for (size_t i = 0; i < len - 12; i++) {
        if (data[i] == 'd' && data[i+1] == 'a' && data[i+2] == 'c' && data[i+3] == '4') {
            strcpy(params->audio_codec, "AC-4");
            
            // AC-4 specific stream structure at i+8 onwards
            if (i + 12 < len) {
                uint8_t presentation_config = data[i+10];
                
                if (presentation_config & 0x20) {
                    strcpy(params->audio_channels, "7.1");
                } else if (presentation_config & 0x10) {
                    strcpy(params->audio_channels, "5.1");
                } else if (presentation_config & 0x08) {
                    strcpy(params->audio_channels, "2.0");
                }
            }
            return;
        }
    }
}

void extract_mmt_media_params_from_mpu(const uint8_t* payload, size_t length, 
                                        const char* asset_type, MmtMediaParams* params) {
    
    // Initialization fragments are typically much larger (100s to 1000s of bytes)
    if (length < 100) {
        return;
    }
    
    MpuHeader mpu;
    if (parse_mpu_header(payload, length, &mpu) < 0) {
        return;
    }
    
    if (mpu.fragment_type != 0) {
        return;
    }
    
    // Also check MFU data size
    if (mpu.mfu_data_length < 50) {
        return;
    }
    
    if (strcmp(asset_type, "video") == 0 || strcmp(asset_type, "Video") == 0) {
        extract_hevc_params(mpu.mfu_data, mpu.mfu_data_length, params);

    } else if (strcmp(asset_type, "audio") == 0 || strcmp(asset_type, "Audio") == 0) {
        extract_ac4_params(mpu.mfu_data, mpu.mfu_data_length, params);

    }
}

// Cache management
void cache_mmt_params(const char* dest_ip, const char* dest_port, 
                      uint16_t packet_id, MmtMediaParams* params) {
    for (int i = 0; i < g_mmt_params_cache_count; i++) {
        if (strcmp(g_mmt_params_cache[i].destIp, dest_ip) == 0 &&
            strcmp(g_mmt_params_cache[i].destPort, dest_port) == 0 &&
            g_mmt_params_cache[i].packet_id == packet_id) {
            g_mmt_params_cache[i].params = *params;
            return;
        }
    }
    
    if (g_mmt_params_cache_count < 100) {
        strcpy(g_mmt_params_cache[g_mmt_params_cache_count].destIp, dest_ip);
        strcpy(g_mmt_params_cache[g_mmt_params_cache_count].destPort, dest_port);
        g_mmt_params_cache[g_mmt_params_cache_count].packet_id = packet_id;
        g_mmt_params_cache[g_mmt_params_cache_count].params = *params;
        g_mmt_params_cache_count++;
    }
}

MmtMediaParams* get_cached_mmt_params(const char* dest_ip, const char* dest_port, 
                                      uint16_t packet_id) {
    for (int i = 0; i < g_mmt_params_cache_count; i++) {
        if (strcmp(g_mmt_params_cache[i].destIp, dest_ip) == 0 &&
            strcmp(g_mmt_params_cache[i].destPort, dest_port) == 0 &&
            g_mmt_params_cache[i].packet_id == packet_id) {
            return &g_mmt_params_cache[i].params;
        }
    }
    return NULL;
}

void process_enhanced_mmt_payload(const u_char* payload, int len, ServiceDestination* dest_info) {
    if (len < 32) return;
    
    mmt_packet_header_t header;
    int header_len = parse_mmt_packet_header(payload, len, &header);
    
    if (header_len < 0) {
        return;
    }
    
    // Record data usage (use packet ID as TSI equivalent for MMT)
    const char* description = get_stream_description(dest_info->destinationIpStr, 
                                                   dest_info->destinationPortStr, 
                                                   header.packet_id);
    record_data_usage(dest_info->destinationIpStr, dest_info->destinationPortStr, 
                     header.packet_id, len, description);
    
    log_mmt_packet_id(header.packet_id);
    
    const uint8_t* payload_start = payload + header_len;
    size_t payload_size = header.payload_length;
    
    // Process signaling packets
    if (header.packet_id == 0 || header.packet_id == dest_info->mmtSignalingPacketId) {

        
        process_enhanced_mmt_signaling_payload(payload_start, payload_size, 
                                             dest_info->destinationIpStr, dest_info->destinationPortStr);
    } else {
        // This is a media packet - extract parameters from initialization MPUs
        const char* asset_type = get_media_type_from_mpt(dest_info->destinationIpStr, 
                                                         dest_info->destinationPortStr, 
                                                         header.packet_id);
        
        if (asset_type && (strcmp(asset_type, "video") == 0 || strcmp(asset_type, "audio") == 0 || 
                          strcmp(asset_type, "Video") == 0 || strcmp(asset_type, "Audio") == 0)) {

            
            MmtMediaParams params = {0};
            extract_mmt_media_params_from_mpu(payload_start, payload_size, asset_type, &params);
            
            if (strlen(params.resolution) > 0 || strlen(params.audio_codec) > 0) {

                cache_mmt_params(dest_info->destinationIpStr, dest_info->destinationPortStr, 
                               header.packet_id, &params);
            } 
        }
    }
    
    free_mmt_packet_header(&header);
}

/**
 * @brief Enhanced MMT signaling processor that handles the actual payload formats found
 */
void process_enhanced_mmt_signaling_payload(const uint8_t* buffer, size_t size, const char* destIp, const char* destPort) {
    if (size < 20) return;
    
    // Look for GZIP magic bytes (1F 8B)
    for (size_t i = 0; i < size - 10; i++) {
        if (buffer[i] == 0x1F && buffer[i+1] == 0x8B) {
            
            const uint8_t* gzip_start = buffer + i;
            size_t gzip_size = size - i;
            
            // Try to decompress
            int decompressed_size = 0;
            int consumed_size = 0;
            char* decompressed = decompress_gzip(gzip_start, gzip_size, &decompressed_size, &consumed_size);
            
            if (decompressed && decompressed_size > 0) {
                // Try to parse as XML
                TableType type = TABLE_TYPE_UNKNOWN;
                void* parsed_data = NULL;
                char source_id[256];
                snprintf(source_id, sizeof(source_id), "MMT GZIP from %s:%s", destIp, destPort);
                
                if (parse_xml(decompressed, decompressed_size, &type, &parsed_data, source_id) == 0 && parsed_data) {
                    store_unique_table(decompressed, decompressed_size, type, parsed_data, destIp, destPort);
                    
                    // If this is a USBD, also extract and store USD tables with proper IP/port
                    if (type == TABLE_TYPE_USBD) {
                        
                        xmlDocPtr doc = xmlReadMemory(decompressed, decompressed_size, "usbd.xml", NULL, XML_PARSE_RECOVER);
                        if (doc) {
                            xmlNodePtr root = xmlDocGetRootElement(doc);
                            xmlNodePtr cur_node = root->children;
                            
                            while (cur_node != NULL) {
                                if (cur_node->type == XML_ELEMENT_NODE && 
                                    xmlStrcmp(cur_node->name, (const xmlChar *)"UserServiceDescription") == 0) {
                                    
                                    char* usd_xml = extract_node_as_xml(cur_node);
                                    if (usd_xml) {
                                        TableType usd_type = TABLE_TYPE_USD;
                                        void* usd_parsed_data = NULL;
                                        if (parse_xml(usd_xml, strlen(usd_xml), &usd_type, &usd_parsed_data, "Nested USD") == 0 && usd_parsed_data) {
                                            store_unique_table(usd_xml, strlen(usd_xml), TABLE_TYPE_USD, usd_parsed_data, destIp, destPort);
                                        }
                                        free(usd_xml);
                                    }
                                }
                                cur_node = cur_node->next;
                            }
                            xmlFreeDoc(doc);
                        }
                    }
                }
                
                free(decompressed);
                return;
            }
        }
    }
    
    // Look for 0x20 (MPT table_id)
    for (size_t i = 0; i < size - 30 && i < size; i++) {
        if (buffer[i] == 0x20 && i > 0) {
            // Check if preceded by proprietary wrapper (0x18) or is standalone
            const uint8_t* mpt_buffer = (i >= 5 && buffer[i-5] == 0x18) ? buffer + i - 5 : buffer + i;
            size_t mpt_size = size - (mpt_buffer - buffer);
            
            ProprietaryMptData* mpt_data = parse_proprietary_mpt(mpt_buffer, mpt_size);
            if (mpt_data && mpt_data->num_assets > 0) {  // ADDED: && mpt_data->num_assets > 0
                char content_id[256];
                snprintf(content_id, sizeof(content_id), "MMT_MPT_Proprietary_%s:%s", destIp, destPort);
                store_unique_table(content_id, strlen(content_id), TABLE_TYPE_MP_TABLE_BINARY, 
                                mpt_data, destIp, destPort);
                return;
            }
            if (mpt_data) free_proprietary_mpt_data(mpt_data);  // Free even if 0 assets
        }
    }
    
    // Look for asset names (common in MP tables)
    const char* asset_patterns[] = {"videoasset", "audioasset", "asset", "hev1", "hvc1", "mp4a", NULL};
    for (int p = 0; asset_patterns[p]; p++) {
        const char* pattern = asset_patterns[p];
        size_t pattern_len = strlen(pattern);
        
        for (size_t i = 0; i < size - pattern_len; i++) {
            if (memcmp(buffer + i, pattern, pattern_len) == 0) {
                
                // Try to parse the whole buffer as binary MP table
                BinaryMptData* parsed_data = parse_enhanced_binary_mp_table(buffer, size);
                if (parsed_data) {
                    char content_id[256];
                    snprintf(content_id, sizeof(content_id), "Asset_Pattern_MPT_%s:%s", destIp, destPort);
                    store_unique_table(content_id, strlen(content_id), 
                                    TABLE_TYPE_MP_TABLE_PATTERN_MATCHED,
                                    parsed_data, destIp, destPort);
                    return;
                }
                break; // Found pattern, no need to continue searching for this one
            }
        }
    }
    
    // Check for other signaling message types
    mmt_signaling_message_t message;
    memset(&message, 0, sizeof(message));
    int msg_len = parse_mmt_signaling_message(buffer, size, &message);
    if (msg_len > 0 && message.payload) {
        process_mmt_signaling_message(&message, destIp, destPort);
        free(message.payload);
        return;
    }
}

/**
 * @brief Precise binary MP table parser with fallback for different formats
 */
BinaryMptData* parse_enhanced_binary_mp_table(const uint8_t* buffer, size_t size) {
    if (size < 20) return NULL;
    
    BinaryMptData* mpt_data = calloc(1, sizeof(BinaryMptData));
    if (!mpt_data) return NULL;
    
    BinaryMptAsset* asset_tail = NULL;
    int assets_found = 0;
    
    // Method 1: Look for FE markers (standard MMT format)
    for (size_t i = 0; i < size - 20; i++) {
        if (buffer[i] == 0xFE) {
            
            // Check if this looks like a valid asset entry
            if (i + 10 < size) {
                // Look for packet ID after FE marker (usually 2-3 bytes after)
                uint16_t packet_id = 0;
                
                // Try different offsets for packet ID
                for (int pid_offset = 3; pid_offset <= 5 && i + pid_offset + 1 < size; pid_offset++) {
                    uint16_t potential_pid = ntohs(*(uint16_t*)(buffer + i + pid_offset));
                    if (potential_pid > 0 && potential_pid < 8192) {
                        packet_id = potential_pid;
                        break;
                    }
                }
                
                // Look backwards from FE marker for asset name
                char asset_name[64] = "";
                
                // Search backwards up to 50 bytes for readable asset name
                for (int back_offset = 1; back_offset <= 50 && back_offset <= i; back_offset++) {
                    size_t check_pos = i - back_offset;
                    
                    // Look for start of readable string
                    if (isalpha(buffer[check_pos]) || isdigit(buffer[check_pos])) {
                        // Find the full string
                        size_t str_start = check_pos;
                        while (str_start > 0 && 
                               (isalnum(buffer[str_start - 1]) || buffer[str_start - 1] == '_' || 
                                buffer[str_start - 1] == '-' || isdigit(buffer[str_start - 1]))) {
                            str_start--;
                        }
                        
                        size_t str_end = check_pos;
                        while (str_end < i && 
                               (isalnum(buffer[str_end]) || buffer[str_end] == '_' || 
                                buffer[str_end] == '-' || isdigit(buffer[str_end]))) {
                            str_end++;
                        }
                        
                        size_t str_len = str_end - str_start;
                        if (str_len >= 4 && str_len < 64) {
                            memcpy(asset_name, buffer + str_start, str_len);
                            asset_name[str_len] = '\0';
                            
                            // Check if this looks like a real asset name
                            if (strstr(asset_name, "Video") || strstr(asset_name, "Audio") || 
                                strstr(asset_name, "Data") || strstr(asset_name, "asset") ||
                                strstr(asset_name, "hev1") || strstr(asset_name, "hvc1") ||
                                strstr(asset_name, "mp4a") || strstr(asset_name, "ac-4") ||
                                strstr(asset_name, "stpp")) {
                                break;
                            }
                        }
                        asset_name[0] = '\0'; // Reset if not a good match
                    }
                }
                
                // Create asset if we found valid name and/or packet ID
                if (strlen(asset_name) > 0 || packet_id > 0) {
                    BinaryMptAsset* asset = calloc(1, sizeof(BinaryMptAsset));
                    if (asset) {
                        if (strlen(asset_name) > 0) {
                            strcpy(asset->assetId, asset_name);
                        } else {
                            snprintf(asset->assetId, sizeof(asset->assetId), "Asset_PID_%u", packet_id);
                        }
                        
                        asset->packetId = packet_id;
                        
                        // Determine asset type from name
                        if (strstr(asset->assetId, "Video") || strstr(asset->assetId, "video") ||
                            strstr(asset->assetId, "hev1") || strstr(asset->assetId, "hvc1")) {
                            strcpy(asset->assetType, "video");
                        } else if (strstr(asset->assetId, "Audio") || strstr(asset->assetId, "audio") ||
                                   strstr(asset->assetId, "mp4a") || strstr(asset->assetId, "ac-4")) {
                            strcpy(asset->assetType, "audio");
                        } else if (strstr(asset->assetId, "Data") || strstr(asset->assetId, "stpp")) {
                            strcpy(asset->assetType, "caption");
                        } else {
                            strcpy(asset->assetType, "unknown");
                        }
                        
                        // Extract codec information from asset name
                        if (strstr(asset->assetId, "hvc1") || strstr(asset->assetId, "hev1")) {
                            strcpy(asset->codec, "HEVC");
                        } else if (strstr(asset->assetId, "ac-4")) {
                            strcpy(asset->codec, "AC-4");
                        } else if (strstr(asset->assetId, "stpp")) {
                            strcpy(asset->codec, "TTML");
                        } else if (strstr(asset->assetId, "mp4a")) {
                            strcpy(asset->codec, "AAC");
                        } else {
                            strcpy(asset->codec, "Unknown");
                        }
                        
                        // Add to linked list
                        if (mpt_data->head_asset == NULL) {
                            mpt_data->head_asset = asset;
                            asset_tail = asset;
                        } else {
                            asset_tail->next = asset;
                            asset_tail = asset;
                        }
                        
                        assets_found++;
                        
                        // Skip ahead past this FE marker to avoid duplicates
                        i += 10;
                    }
                }
            }
        }
    }
    
    // Method 2: Fallback - if no FE markers, look for clear asset name patterns
    if (assets_found == 0) {
        
        // Look for specific asset patterns
        const char* asset_patterns[] = {"videoasset", "audioasset", NULL};
        
        for (int p = 0; asset_patterns[p]; p++) {
            const char* pattern = asset_patterns[p];
            size_t pattern_len = strlen(pattern);
            
            for (size_t i = 0; i < size - pattern_len; i++) {
                if (memcmp(buffer + i, pattern, pattern_len) == 0) {
                    
                    // Find the complete asset name
                    size_t name_start = i;
                    size_t name_end = i + pattern_len;
                    
                    // Extend the name to include numbers, codec info, etc.
                    while (name_end < size && 
                           (isalnum(buffer[name_end]) || buffer[name_end] == '_' || 
                            buffer[name_end] == '-' || isdigit(buffer[name_end]))) {
                        name_end++;
                    }
                    
                    size_t name_len = name_end - name_start;
                    if (name_len >= pattern_len && name_len < 64) {
                        char asset_name[64];
                        memcpy(asset_name, buffer + name_start, name_len);
                        asset_name[name_len] = '\0';
                        
                        // Look for packet ID near this asset (within 20 bytes)
                        uint16_t packet_id = 0;
                        for (int offset = -10; offset <= 10; offset++) {
                            size_t check_pos = i + offset;
                            if (check_pos > 0 && check_pos + 1 < size) {
                                uint16_t potential_pid = ntohs(*(uint16_t*)(buffer + check_pos));
                                if (potential_pid > 0 && potential_pid < 8192) {
                                    packet_id = potential_pid;
                                    break;
                                }
                            }
                        }
                        
                        BinaryMptAsset* asset = calloc(1, sizeof(BinaryMptAsset));
                        if (asset) {
                            strcpy(asset->assetId, asset_name);
                            asset->packetId = packet_id;
                            
                            // Determine asset type
                            if (strstr(asset_name, "video")) {
                                strcpy(asset->assetType, "video");
                            } else if (strstr(asset_name, "audio")) {
                                strcpy(asset->assetType, "audio");
                            } else {
                                strcpy(asset->assetType, "unknown");
                            }
                            
                            // Add to linked list
                            if (mpt_data->head_asset == NULL) {
                                mpt_data->head_asset = asset;
                                asset_tail = asset;
                            } else {
                                asset_tail->next = asset;
                                asset_tail = asset;
                            }
                            
                            assets_found++;
                            
                            // Skip past this asset to avoid duplicates
                            i = name_end - 1;
                            break; // Break out of pattern loop for this position
                        }
                    }
                }
            }
        }
    }
    
    if (assets_found == 0) {
        free(mpt_data);
        return NULL;
    }
    
    return mpt_data;
}

/**
 * @brief Cleanup functions
 */
void free_mmt_packet_header(mmt_packet_header_t* header) {
    if (header && header->extension_data) {
        free(header->extension_data);
        header->extension_data = NULL;
    }
}

/**
 * @brief Logs a seen MMT Packet ID and increments its count.
 */
void log_mmt_packet_id(uint16_t packet_id) {
    // Only log the first occurrence of each packet ID
    if (!packet_id_seen[packet_id]) {
        packet_id_seen[packet_id] = true;
    }
    
    // Still maintain the count for statistics
    for (int i = 0; i < g_packet_id_log_count; i++) {
        if (g_packet_id_log[i].id == packet_id) {
            g_packet_id_log[i].count++;
            return;
        }
    }

    if (g_packet_id_log_count < MAX_UNIQUE_PIDS) {
        g_packet_id_log[g_packet_id_log_count].id = packet_id;
        g_packet_id_log[g_packet_id_log_count].count = 1;
        g_packet_id_log_count++;
    }
}

/**
 * @brief Prints the summary of all unique MMT packet IDs and their counts.
 */
void print_packet_id_log() {
    printf("\n--- MMT Packet ID Summary ---\n");
    if (g_packet_id_log_count == 0) {
        printf("No MMT packets were found on the monitored streams.\n");
        return;
    }
    printf("Found %d unique Packet IDs:\n", g_packet_id_log_count);
    printf("----------------------------------\n");
    printf("| Packet ID   |  Packet Count  |\n");
    printf("----------------------------------\n");
    for (int i = 0; i < g_packet_id_log_count; i++) {
        printf("| %-11u | %-14d |\n", g_packet_id_log[i].id, g_packet_id_log[i].count);
    }
    printf("----------------------------------\n");
    printf("Tip: The signaling packet ID (for the MP Table) usually has a very low count compared to media packets.\n\n");
}

// Comparison function for sorting data usage by bytes (descending)
int compare_data_usage(const void *a, const void *b) {
    const DataUsageEntry *entry_a = (const DataUsageEntry *)a;
    const DataUsageEntry *entry_b = (const DataUsageEntry *)b;
    
    // First compare by IP address
    int ip_cmp = strcmp(entry_a->destinationIp, entry_b->destinationIp);
    if (ip_cmp != 0) return ip_cmp;
    
    // If IPs are the same, compare by port
    int port_cmp = strcmp(entry_a->destinationPort, entry_b->destinationPort);
    if (port_cmp != 0) return port_cmp;
    
    // If IPs and ports are the same, compare by TSI/Packet ID
    if (entry_a->tsi_or_packet_id < entry_b->tsi_or_packet_id) return -1;
    if (entry_a->tsi_or_packet_id > entry_b->tsi_or_packet_id) return 1;
    return 0;
}

// Add this new comparison function for sorting by bytes
int compare_data_usage_by_bytes(const void *a, const void *b) {
    const DataUsageEntry *entry_a = (const DataUsageEntry *)a;
    const DataUsageEntry *entry_b = (const DataUsageEntry *)b;
    
    // Sort by total bytes (descending)
    if (entry_a->total_bytes > entry_b->total_bytes) return -1;
    if (entry_a->total_bytes < entry_b->total_bytes) return 1;
    return 0;
}

void consolidate_data_usage_entries() {
    
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry_i = &g_data_usage[i];
        if (entry_i->total_bytes == 0) continue; // Already consolidated
        
        // Look for other entries with same IP:port and media type
        for (int j = i + 1; j < g_data_usage_count; j++) {
            DataUsageEntry* entry_j = &g_data_usage[j];
            if (entry_j->total_bytes == 0) continue; // Already consolidated
            
            // Same service and protocol?
            if (strcmp(entry_i->destinationIp, entry_j->destinationIp) == 0 &&
                strcmp(entry_i->destinationPort, entry_j->destinationPort) == 0 &&
                strcmp(entry_i->stream_type, entry_j->stream_type) == 0) {
                
                // Both are MMT and have similar media types?
                if (strcmp(entry_i->stream_type, "MMT") == 0) {
                    const char* type_i = get_media_type_from_mpt(entry_i->destinationIp, entry_i->destinationPort, entry_i->tsi_or_packet_id);
                    const char* type_j = get_media_type_from_mpt(entry_j->destinationIp, entry_j->destinationPort, entry_j->tsi_or_packet_id);
                    
                    // Consolidate if same media type (e.g., all "Data/Captions" entries)
                    if (strcmp(type_i, type_j) == 0 && 
                        (strcmp(type_i, "Data/Captions") == 0 || strcmp(type_i, "caption") == 0)) {
                        
                        //printf("DEBUG: Consolidating MMT %s entries: PID %u + PID %u\n", 
                        //       type_i, entry_i->tsi_or_packet_id, entry_j->tsi_or_packet_id);
                        
                        // Merge j into i
                        entry_i->total_bytes += entry_j->total_bytes;
                        entry_i->packet_count += entry_j->packet_count;
                        
                        // Update description to show consolidation
                        snprintf(entry_i->description, sizeof(entry_i->description), 
                                "%s - MMT %s (Multiple PIDs)", 
                                get_service_name_for_destination(entry_i->destinationIp, entry_i->destinationPort),
                                type_i);
                        
                        // Mark j as consolidated
                        entry_j->total_bytes = 0;
                        entry_j->packet_count = 0;
                    }
                }
            }
        }
    }
    
    // Remove consolidated (empty) entries
    int write_idx = 0;
    for (int read_idx = 0; read_idx < g_data_usage_count; read_idx++) {
        if (g_data_usage[read_idx].total_bytes > 0) {
            if (write_idx != read_idx) {
                g_data_usage[write_idx] = g_data_usage[read_idx];
            }
            write_idx++;
        }
    }
    
    //int removed = g_data_usage_count - write_idx;
    g_data_usage_count = write_idx;
}

void generate_data_usage_chart(FILE *f) {
    if (g_data_usage_count == 0 || g_total_capture_bytes == 0) {
        return;
    }
    
    // Sort entries by total bytes (descending)
    qsort(g_data_usage, g_data_usage_count, sizeof(DataUsageEntry), compare_data_usage_by_bytes);
    
    fprintf(f, "<h2>ATSC 3.0 Data Usage Analysis</h2>\n");
    fprintf(f, "<script>\n");
    fprintf(f, "function sortTable(n) {\n");
    fprintf(f, "  var table = document.getElementById('usageTable');\n");
    fprintf(f, "  var rows = Array.from(table.rows).slice(1);\n");
    fprintf(f, "  var dir = table.getAttribute('data-sort-dir') === 'asc' ? 'desc' : 'asc';\n");
    fprintf(f, "  \n");
    fprintf(f, "  rows.sort(function(a, b) {\n");
    fprintf(f, "    var aVal = a.cells[n].textContent.trim();\n");
    fprintf(f, "    var bVal = b.cells[n].textContent.trim();\n");
    fprintf(f, "    \n");
    fprintf(f, "    // Handle percentage and data size columns\n");
    fprintf(f, "    if (n === 1) { // Usage column - extract percentage\n");
    fprintf(f, "      aVal = parseFloat(aVal.match(/([0-9.]+)%%/)[1]);\n");
    fprintf(f, "      bVal = parseFloat(bVal.match(/([0-9.]+)%%/)[1]);\n");
    fprintf(f, "    } else if (n === 4) { // Total Data column - convert to bytes\n");
    fprintf(f, "      aVal = parseDataSize(aVal);\n");
    fprintf(f, "      bVal = parseDataSize(bVal);\n");
    fprintf(f, "    } else if (n === 5) { // Bitrate column - convert to bps\n");
    fprintf(f, "      aVal = parseBitrate(aVal);\n");
    fprintf(f, "      bVal = parseBitrate(bVal);\n");
    fprintf(f, "    }\n");
    fprintf(f, "    \n");
    fprintf(f, "    if (typeof aVal === 'number' && typeof bVal === 'number') {\n");
    fprintf(f, "      return dir === 'asc' ? aVal - bVal : bVal - aVal;\n");
    fprintf(f, "    } else {\n");
    fprintf(f, "      return dir === 'asc' ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);\n");
    fprintf(f, "    }\n");
    fprintf(f, "  });\n");
    fprintf(f, "  \n");
    fprintf(f, "  // Clear existing rows and add sorted ones\n");
    fprintf(f, "  while(table.rows.length > 1) table.deleteRow(1);\n");
    fprintf(f, "  rows.forEach(function(row) { table.appendChild(row); });\n");
    fprintf(f, "  \n");
    fprintf(f, "  table.setAttribute('data-sort-dir', dir);\n");
    fprintf(f, "  \n");
    fprintf(f, "  // Update header arrows\n");
    fprintf(f, "  var headers = table.querySelectorAll('th');\n");
    fprintf(f, "  headers.forEach(function(th, i) {\n");
    fprintf(f, "    th.style.cursor = 'pointer';\n");
    fprintf(f, "    if (i === n) {\n");
    fprintf(f, "      th.innerHTML = th.innerHTML.replace(/ [↑↓]/g, '') + (dir === 'asc' ? ' ↑' : ' ↓');\n");
    fprintf(f, "    } else {\n");
    fprintf(f, "      th.innerHTML = th.innerHTML.replace(/ [↑↓]/g, '');\n");
    fprintf(f, "    }\n");
    fprintf(f, "  });\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");
    fprintf(f, "function parseDataSize(str) {\n");
    fprintf(f, "  var match = str.match(/([0-9.]+)\\s*(MB|KB|bytes)/i);\n");
    fprintf(f, "  if (!match) return 0;\n");
    fprintf(f, "  var val = parseFloat(match[1]);\n");
    fprintf(f, "  var unit = match[2].toUpperCase();\n");
    fprintf(f, "  if (unit === 'MB') return val * 1000000;\n");
    fprintf(f, "  if (unit === 'KB') return val * 1000;\n");
    fprintf(f, "  return val;\n");
    fprintf(f, "}\n");
    fprintf(f, "\n");
    fprintf(f, "function parseBitrate(str) {\n");
    fprintf(f, "  if (str === 'N/A') return 0;\n");
    fprintf(f, "  var match = str.match(/([0-9.]+)\\s*(Mbps|Kbps|bps)/i);\n");
    fprintf(f, "  if (!match) return 0;\n");
    fprintf(f, "  var val = parseFloat(match[1]);\n");
    fprintf(f, "  var unit = match[2].toLowerCase();\n");
    fprintf(f, "  if (unit === 'mbps') return val * 1000000;\n");
    fprintf(f, "  if (unit === 'kbps') return val * 1000;\n");
    fprintf(f, "  return val;\n");
    fprintf(f, "}\n");
    fprintf(f, "</script>\n");
    fprintf(f, "<table id='usageTable' style='width:100%%;margin:0;border-collapse:collapse;' data-sort-dir='desc'>\n");
    fprintf(f, "<thead><tr>");
    fprintf(f, "<th onclick='sortTable(0)' style='cursor:pointer;'>IP:Port (ID)</th>");
    fprintf(f, "<th onclick='sortTable(1)' style='cursor:pointer;'>Usage ↓</th>");
    fprintf(f, "<th onclick='sortTable(2)' style='cursor:pointer;'>Service</th>");
    fprintf(f, "<th onclick='sortTable(3)' style='cursor:pointer;'>Type</th>");
    fprintf(f, "<th onclick='sortTable(4)' style='cursor:pointer;'>Total Data</th>");
    fprintf(f, "<th onclick='sortTable(5)' style='cursor:pointer;'>Bitrate</th>");
    fprintf(f, "</tr></thead>\n");
    
    for (int i = 0; i < g_data_usage_count; i++) {
        DataUsageEntry* entry = &g_data_usage[i];
        double percentage = (double)entry->total_bytes / g_total_capture_bytes * 100.0;
        
        // Determine bar color based on stream type and media content
        const char* bar_color;
        if (entry->is_lls) {
            bar_color = "#00aa00"; // Green for LLS
        } else if (entry->is_signaling) {
            bar_color = "#ff6600"; // Orange for all signaling
        } else if (strcmp(entry->stream_type, "ROUTE") == 0) {
            // Get specific media type for ROUTE streams
            const char* route_media_type = get_media_type_from_stsid(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strstr(route_media_type, "video") || strstr(route_media_type, "Video")) {
                bar_color = "#0066cc"; // Blue for ROUTE video
            } else if (strstr(route_media_type, "audio") || strstr(route_media_type, "Audio")) {
                bar_color = "#00cc00"; // Green for ROUTE audio
            } else if (strstr(route_media_type, "caption") || strstr(route_media_type, "Data")) {
                bar_color = "#cc00cc"; // Pink for ROUTE captions/data
            } else {
                bar_color = "#424242"; // Dark gray for other ROUTE media
            }
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            // Get specific media type for MMT streams
            const char* mmt_media_type = get_media_type_from_mpt(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strstr(mmt_media_type, "video") || strstr(mmt_media_type, "Video")) {
                bar_color = "#0066cc"; // Blue for MMT video
            } else if (strstr(mmt_media_type, "audio") || strstr(mmt_media_type, "Audio")) {
                bar_color = "#00cc00"; // Green for MMT audio
            } else if (strstr(mmt_media_type, "caption") || strstr(mmt_media_type, "Data")) {
                bar_color = "#cc00cc"; // Pink for MMT captions/data
            } else {
                bar_color = "#424242"; // Dark gray for other MMT media
            }
        } else {
            bar_color = "#999999"; // Gray for other/unknown
        }
        
        // Calculate bandwidth if timing available
        char bandwidth_str[64] = "N/A";
        if (g_input_type == INPUT_TYPE_PCAP && g_pcap_timing_valid && g_packet_count > 1) {
            double duration_seconds = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) + 
                                     (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
            if (duration_seconds > 0) {
                double bps = entry->total_bytes * 8.0 / duration_seconds;
                if (bps >= 1000000) {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.2f Mbps", bps / 1000000.0);
                } else if (bps >= 1000) {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.1f Kbps", bps / 1000.0);
                } else {
                    snprintf(bandwidth_str, sizeof(bandwidth_str), "%.0f bps", bps);
                }
            }
        }
        
        // Format total data size
        char data_size_str[64];
        if (entry->total_bytes >= 1000000) {
            snprintf(data_size_str, sizeof(data_size_str), "%.2f MB", entry->total_bytes / 1000000.0);
        } else if (entry->total_bytes >= 1000) {
            snprintf(data_size_str, sizeof(data_size_str), "%.1f KB", entry->total_bytes / 1000.0);
        } else {
            snprintf(data_size_str, sizeof(data_size_str), "%llu bytes", (unsigned long long)entry->total_bytes);
        }
        
        // Extract service name and media type from description
        const char* service_name = get_service_name_for_destination(entry->destinationIp, entry->destinationPort);
        if (!service_name) {
            service_name = "Unknown Service";
        }
        
        // Determine media type based on stream analysis
        const char* media_type = "Unknown";
        if (entry->is_lls) {
            media_type = "LLS Signaling";
        } else if (entry->is_signaling) {
            media_type = "Service Signaling";
        } else if (strcmp(entry->stream_type, "ROUTE") == 0) {
            media_type = get_media_type_from_stsid(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strcmp(media_type, "Media") == 0) {
                media_type = "ROUTE Media";
            }
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            media_type = get_media_type_from_mpt(entry->destinationIp, entry->destinationPort, entry->tsi_or_packet_id);
            if (strcmp(media_type, "Media") == 0) {
                media_type = "MMT Media";
            }
        } else {
            media_type = entry->stream_type;
        }
        
        fprintf(f, "<tr>\n");
        
        // Column 1: IP:Port (ID)
        fprintf(f, "  <td style='font-size:small;'>%s:%s", entry->destinationIp, entry->destinationPort);
        if (strcmp(entry->stream_type, "ROUTE") == 0) {
            fprintf(f, " (TSI %u)", entry->tsi_or_packet_id);
        } else if (strcmp(entry->stream_type, "MMT") == 0) {
            if (entry->tsi_or_packet_id == 0) {
                fprintf(f, " (PID 0)");
            } else {
                fprintf(f, " (PID %u)", entry->tsi_or_packet_id);
            }
        } else if (entry->is_lls) {
            fprintf(f, " (LLS)");
        } else if (is_bps_service(entry->destinationIp, entry->destinationPort)) {
            fprintf(f, " (BPS)");
        }
        fprintf(f, "</td>\n");
        
        // Column 2: Usage (bar + percentage)
        fprintf(f, "  <td style='width:30%%;'>");
        fprintf(f, "<div style='background-color:%s;width:%.1f%%;height:16px;display:inline-block;'></div> %.2f%%", 
                bar_color, percentage > 50.0 ? 50.0 : percentage, percentage);
        fprintf(f, "</td>\n");
        
        // Column 3: Service
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", service_name);
        
        // Column 4: Type
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", media_type);
        
        // Column 5: Total Data
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", data_size_str);
        
        // Column 6: Bitrate
        fprintf(f, "  <td style='font-size:small;'>%s</td>\n", bandwidth_str);
        
        fprintf(f, "</tr>\n");
    }
    
    fprintf(f, "</table>\n");
    
    // Add summary stats
    uint64_t signaling_bytes = 0, media_bytes = 0, other_bytes = 0;
    for (int i = 0; i < g_data_usage_count; i++) {
        if (g_data_usage[i].is_signaling || g_data_usage[i].is_lls) {
            signaling_bytes += g_data_usage[i].total_bytes;
        } else if (strcmp(g_data_usage[i].stream_type, "Other UDP") == 0) {
            other_bytes += g_data_usage[i].total_bytes;
        } else {
            media_bytes += g_data_usage[i].total_bytes;
        }
    }
    
    fprintf(f, "<p style='font-size:small;margin-top:10px;'>\n");
    fprintf(f, "Total: %.2f MB | Signaling: %.2f%% | Media: %.2f%% | Other: %.2f%%\n", 
            g_total_capture_bytes / 1000000.0,
            (double)signaling_bytes / g_total_capture_bytes * 100.0,
            (double)media_bytes / g_total_capture_bytes * 100.0,
            (double)other_bytes / g_total_capture_bytes * 100.0);
    fprintf(f, "</p>\n");
}

// Helper function to find highest resolution video representation
MpdRepresentation* find_highest_resolution_video(MpdAdaptationSet* as) {
    if (!as || (strcmp(as->contentType, "video") != 0 && strcmp(as->mimeType, "video/mp4") != 0)) {
        return NULL;
    }
    
    MpdRepresentation* best_rep = NULL;
    int best_pixels = 0;
    
    MpdRepresentation* rep = as->head_rep;
    while (rep) {
        if (strlen(rep->width) > 0 && strlen(rep->height) > 0) {
            int width = atoi(rep->width);
            int height = atoi(rep->height);
            int pixels = width * height;
            
            if (pixels > best_pixels) {
                best_pixels = pixels;
                best_rep = rep;
            }
        }
        rep = rep->next;
    }
    
    return best_rep;
}

// Helper function to format bandwidth
void format_bandwidth(const char* bandwidth_str, char* output, size_t output_size) {
    if (strlen(bandwidth_str) == 0) {
        strcpy(output, "Unknown");
        return;
    }
    
    int bw = atoi(bandwidth_str);
    if (bw >= 1000000) {
        snprintf(output, output_size, "%.1f Mbps", bw / 1000000.0);
    } else if (bw >= 1000) {
        snprintf(output, output_size, "%.0f kbps", bw / 1000.0);
    } else {
        snprintf(output, output_size, "%d bps", bw);
    }
}

// Helper function to format audio sample rate
void format_sample_rate(const char* sample_rate_str, char* output, size_t output_size) {
    if (strlen(sample_rate_str) == 0) {
        strcpy(output, "Unknown");
        return;
    }
    
    int sample_rate = atoi(sample_rate_str);
    if (sample_rate >= 1000) {
        snprintf(output, output_size, "%.0f kHz", sample_rate / 1000.0);
    } else {
        snprintf(output, output_size, "%s Hz", sample_rate_str);
    }
}

// Helper function to determine app type from HELD data
const char* determine_app_type(HeldData* held_data) {
    if (!held_data) return "No";
    
    // Check bbandEntryPageUrl for known patterns
    if (strlen(held_data->bbandEntryPageUrl) > 0) {
        if (strstr(held_data->bbandEntryPageUrl, "gameloop") || strstr(held_data->bbandEntryPageUrl, "GameLoop")) {
            return "<a href='https://gameloop.tv/' target='_blank'>GameLoop</a>";
        }
        if (strstr(held_data->bbandEntryPageUrl, "roxi") || strstr(held_data->bbandEntryPageUrl, "Roxi")) {
            return "<a href='https://roxi.tv/' target='_blank'>ROXi</a>";
        }
        if (strstr(held_data->bbandEntryPageUrl, "run3tv") || strstr(held_data->bbandEntryPageUrl, "Run3TV") || strstr(held_data->bbandEntryPageUrl, "A3FA") || strstr(held_data->bbandEntryPageUrl, "a3fa")) {
            return "<a href='https://run3tv.com/' target='_blank'>Run3TV</a>";
        }
    }
    
    // Check clearBbandEntryPageUrl as well
    if (strlen(held_data->clearBbandEntryPageUrl) > 0) {
        if (strstr(held_data->clearBbandEntryPageUrl, "gameloop") || strstr(held_data->clearBbandEntryPageUrl, "GameLoop")) {
            return "<a href='https://gameloop.tv/' target='_blank'>GameLoop</a>";
        }
        if (strstr(held_data->clearBbandEntryPageUrl, "roxi") || strstr(held_data->clearBbandEntryPageUrl, "Roxi")) {
            return "<a href='https://roxi.tv/' target='_blank'>ROXi</a>";
        }
        if (strstr(held_data->clearBbandEntryPageUrl, "run3tv") || strstr(held_data->clearBbandEntryPageUrl, "Run3TV") || strstr(held_data->clearBbandEntryPageUrl, "A3FA") || strstr(held_data->bbandEntryPageUrl, "a3fa")) {
            return "<a href='https://run3tv.com/' target='_blank'>Run3TV</a>";
        }
    }
    
    // If HELD data exists but doesn't match known patterns
    return "Yes";
}

// Add this function to generate the KEYDATA section
void generate_keydata_section(FILE *f) {
    // Get current time in the required format
    time_t current_time = time(NULL);
    char time_str[32];
    struct tm *current_tm = gmtime(&current_time);  // Use GMT like the example
    strftime(time_str, sizeof(time_str), "%d-%b-%Y %H:%M:%S", current_tm);
    
    // Find BSID from SLT data
    char bsid[16] = "Unknown";
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            if (strlen(slt_data->bsid) > 0) {
                strncpy(bsid, slt_data->bsid, sizeof(bsid) - 1);
                bsid[sizeof(bsid) - 1] = '\0';
                break;
            }
        }
    }
    
    // Count programs in categories 1 and 2
    int program_count = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while(service) {
                int category = atoi(service->serviceCategory);
                if (category == 1 || category == 2) {
                    program_count++;
                }
                service = service->next;
            }
        }
    }
    
    fprintf(f, "<!--KEYDATA>\n");
    fprintf(f, "Channel: Unknown\n");
    fprintf(f, "BSID: %s\n", bsid);
    fprintf(f, "TEI: 0\n");
    fprintf(f, "Time: %s\n", time_str);
    fprintf(f, "Programs: %d\n", program_count);
    
    // Generate program entries for categories 1 and 2 only
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while(service) {
                int category = atoi(service->serviceCategory);
                if (category == 1 || category == 2) {
                    // Find MPD data for this service to get technical details
                    MpdData* service_mpd = NULL;
                    MpdRepresentation* video_rep = NULL;
                    MpdRepresentation* audio_rep = NULL;
                    
                    for (int j = 0; j < g_lls_table_count; j++) {
                        if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                            strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                            g_lls_tables[j].type == TABLE_TYPE_MPD) {
                            service_mpd = (MpdData*)g_lls_tables[j].parsed_data;
                            break;
                        }
                    }
                    
                    // Find video and audio representations
                    if (service_mpd) {
                        MpdAdaptationSet* as = service_mpd->head_as;
                        while (as) {
                            if ((strcmp(as->contentType, "video") == 0 || strcmp(as->mimeType, "video/mp4") == 0) && !video_rep) {
                                video_rep = find_highest_resolution_video(as);
                            } else if ((strcmp(as->contentType, "audio") == 0 || strcmp(as->mimeType, "audio/mp4") == 0) && !audio_rep) {
                                // Find audio with most channels
                                MpdRepresentation* rep = as->head_rep;
                                int max_channels = 0;
                                while (rep) {
                                    if (strlen(rep->audioChannelCount) > 0) {
                                        int channels = atoi(rep->audioChannelCount);
                                        if (channels > max_channels) {
                                            max_channels = channels;
                                            audio_rep = rep;
                                        }
                                    }
                                    rep = rep->next;
                                }
                            }
                            as = as->next;
                        }
                    }
                    
                    // Format channel number
                    char channel_str[32] = "";
                    if (strlen(service->majorChannelNo) > 0 && strlen(service->minorChannelNo) > 0) {
                        snprintf(channel_str, sizeof(channel_str), "%s.%s", service->majorChannelNo, service->minorChannelNo);
                    } else {
                        strcpy(channel_str, "0.0");
                    }
                    
                    // Format IP:Port as service identifier
                    char ip_port[64];
                    snprintf(ip_port, sizeof(ip_port), "%s:%s", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
                    
                    // Start building the program line
                    fprintf(f, "%s|%s|%s|%s|", 
                           service->serviceId, 
                           channel_str, 
                           ip_port, 
                           service->shortServiceName);
                    
                    // Video information
                    if (video_rep && strlen(video_rep->width) > 0 && strlen(video_rep->height) > 0) {
                        char scan_type = (strlen(video_rep->scanType) > 0 && strcmp(video_rep->scanType, "progressive") == 0) ? 'p' : 'i';
                        fprintf(f, "0|0|%s|%s%c|%sx%s|", 
                               video_rep->codecs, 
                               video_rep->height, scan_type,
                               video_rep->width, video_rep->height);
                        
                        // Display aspect ratio
                        if (strlen(video_rep->displayAspectRatio) > 0) {
                            fprintf(f, "%s|", video_rep->displayAspectRatio);
                        } else {
                            fprintf(f, "16:9|");  // Default assumption
                        }
                        
                        // Video bitrates (placeholder zeros for now)
                        fprintf(f, "0|0|0|");
                    } else {
                        // No video data available
                        fprintf(f, "0|0|Unknown|Unknown|Unknown|Unknown|0|0|0|");
                    }
                    
                    // Audio information  
                    if (audio_rep) {
                        fprintf(f, "0|0|%s|", audio_rep->codecs);
                        
                        // Audio channels
                        if (strlen(audio_rep->audioChannelCount) > 0) {
                            int channels = atoi(audio_rep->audioChannelCount);
                            if (channels == 1) {
                                fprintf(f, "1.0|");
                            } else if (channels == 2) {
                                fprintf(f, "2.0|");
                            } else if (channels == 6) {
                                fprintf(f, "5.1|");
                            } else {
                                fprintf(f, "%d.0|", channels);
                            }
                        } else {
                            fprintf(f, "Unknown|");
                        }
                        
                        // Audio bitrate
                        if (strlen(audio_rep->bandwidth) > 0) {
                            int bw_bps = atoi(audio_rep->bandwidth);
                            int bw_kbps = bw_bps / 1000;
                            fprintf(f, "%d|", bw_kbps);
                        } else {
                            fprintf(f, "0|");
                        }
                    } else {
                        // No audio data available
                        fprintf(f, "0|0|Unknown|Unknown|0|");
                    }
                    
                    // End with language count and terminator
                    fprintf(f, "1|^|\n");
                }
                service = service->next;
            }
        }
    }
    
    fprintf(f, "-->\n");
}

int get_plps_for_service_enhanced(const char* dest_ip, const char* dest_port, char* plp_list, size_t plp_list_size) {
    if (!dest_ip || !dest_port || !plp_list || plp_list_size == 0) {
        return 0;
    }
    
    plp_list[0] = '\0';
    int plp_count = 0;
    int plps_found[64] = {0};
    
    // Search through all LMT tables
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_LMT) {
            LmtData* lmt_data = (LmtData*)g_lls_tables[i].parsed_data;
            LmtService* service = lmt_data->services;
            
            while (service) {
                LmtMulticast* multicast = service->multicasts;
                while (multicast) {
                    // Check if this multicast destination matches the service
                    if (strcmp(multicast->dest_ip_str, dest_ip) == 0 && 
                        strcmp(multicast->dest_port_str, dest_port) == 0) {
                        
                        if (!plps_found[service->plp_id]) {
                            plps_found[service->plp_id] = 1;
                            plp_count++;
                        }
                    }
                    multicast = multicast->next;
                }
                service = service->next;
            }
        }
    }
    
    // Build the PLP list string
    int first = 1;
    for (int plp = 0; plp < 64; plp++) {
        if (plps_found[plp]) {
            if (!first) {
                strncat(plp_list, "+", plp_list_size - strlen(plp_list) - 1);
            }
            char plp_str[8];
            snprintf(plp_str, sizeof(plp_str), "%d", plp);
            strncat(plp_list, plp_str, plp_list_size - strlen(plp_list) - 1);
            first = 0;
        }
    }
    
    return plp_count;
}

/**
 * @brief Check if any LMT tables are present in the parsed data
 */
int has_lmt_data(void) {
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_LMT) {
            return 1;
        }
    }
    return 0;
}

/**
 * @brief Generates the final HTML report from the stored LLS tables.
 */
void generate_html_report(const char* filename) {
    FILE *f = fopen(filename, "w");
    if (f == NULL) {
        perror("Error opening HTML report file");
        return;
    }

    fprintf(f, "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n");
    fprintf(f, "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n");
    fprintf(f, "<title>RENDER - RabbitEars NextGen Data Evaluator Report - v0.1</title>\n");
    
    generate_keydata_section(f);
    
    fprintf(f, "<style>\n"
           "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji'; font-size: 14px; line-height: 1.4; margin: 1em; background-color: #f8f9fa; color: #212529; }\n"
           "h1, h2, h3, h4, h5 { margin-top: 0.4em; margin-bottom: 0.6em; color: #343a40; }\n"
           "h1 { font-size: 2em; border-bottom: 2px solid #007bff; padding-bottom: 0.3em; }\n"
           "h2 { font-size: 1.6em; border-bottom: 1px solid #dee2e6; padding-bottom: 0.2em; margin-top: 1.0em;}\n"
           "h3 { font-size: 1.3em; }\n"
           "h4 { font-size: 1.1em; color: #495057; }\n"
           "table { border-collapse: collapse; width: 100%%; margin-top: 0.8em; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }\n"
           "th, td { border: 1px solid #dee2e6; padding: 6px 10px; text-align: left; vertical-align: top; word-break: break-word; }\n"
           "th { background-color: #e9ecef; color: #495057; font-weight: 600; }\n"
           "tr:nth-child(even) { background-color: #f8f9fa; }\n"
           "ul { list-style-type: none; padding-left: 0; }\n"
           "li { background-color: #ffffff; border-left: 3px solid #007bff; margin-bottom: 5px; padding: 8px 12px; }\n"
           "li strong { color: #0056b3; }\n"
           ".container { background-color: white; padding: 1.5em; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); max-width: 1200px; margin: auto; }\n"
           ".service-container { border: 2px solid #007bff; border-radius: 8px; padding: 1em; margin-top: 1em; background: #f8f9fa;}\n"
           ".not-found { color: #6c757d; }\n"
           ".mpd-summary { background-color: #e7f3ff; border: 1px solid #b3d7ff; padding: 12px; border-radius: 5px; margin-bottom: 0.8em; }\n"
           ".segment-list { padding-left: 20px; list-style-type: disc; }\n"
           ".segment-list li { border: none; background-color: transparent; padding: 2px; margin-bottom: 2px; }\n"
           "details { border: 1px solid #dee2e6; border-radius: 5px; margin: 1em 0; background-color: #fff; }\n"
           "summary { font-weight: bold; padding: 8px 12px; background-color: #f8f9fa; cursor: pointer; border-bottom: 1px solid #dee2e6; }\n"
           "details[open] > summary { border-bottom: 1px solid #dee2e6; }\n"
           ".details-content { padding: 0.5em 1em 1em 1em; }\n"
           "pre { background-color: #e9ecef; padding: 12px; margin: 0; border-radius: 4px; white-space: pre-wrap; word-wrap: break-word; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, Courier, monospace; font-size: 13px; color: #333; max-height: 300px; overflow-y: auto; }\n"
           "details:not([open]) pre { display: none; }\n"
           "</style>\n</head>\n<body>\n<div class='container'>\n");
    fprintf(f, "<h1>RENDER - RabbitEars NextGen Data Evaluator Report - v0.1</h1>\n");
    
    // --- L1 Information Section ---
    if (get_enhanced_l1_signaling_data()) {
        generate_enhanced_l1_section(f, get_enhanced_l1_signaling_data());
    } else if (get_l1_signaling_data()) {
        // Add a function to generate basic L1 section or convert the data
        generate_basic_l1_section(f, get_l1_signaling_data());
    } else {
        // If no L1 data is available, show the red message similar to CDT
        fprintf(f, "<div class='details-content' style='margin-top: 1em; padding: 10px; border-radius: 5px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24;'>\n");
        fprintf(f, "<strong>PLP/L1 Information Not Available</strong>\n");
        fprintf(f, "</div>\n");
    }
    
    // LMT Tables
    int lmt_count = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_LMT) {
            lmt_count++;
            LmtData* lmt_data = (LmtData*)g_lls_tables[i].parsed_data;
            
            // Count total multicast entries
            int total_multicast_count = 0;
            LmtService* count_service = lmt_data->services;
            while (count_service) {
                LmtMulticast* count_multicast = count_service->multicasts;
                while (count_multicast) {
                    total_multicast_count++;
                    count_multicast = count_multicast->next;
                }
                count_service = count_service->next;
            }

            fprintf(f, "<details><summary>Link Mapping Table (LMT) Version %d - %d Services</summary>\n", 
                    lmt_data->lmt_version, total_multicast_count);
            fprintf(f, "<div class='details-content'>\n");
            fprintf(f, "<table><thead><tr><th>PLP ID</th><th>Source IP:Port</th><th>Destination IP:Port</th><th>Service ID</th><th>Service Name</th><th>Flags</th></tr></thead><tbody>\n");
            
            LmtService* service = lmt_data->services;
            while (service) {
                LmtMulticast* multicast = service->multicasts;
                while (multicast) {
                    // Build flags string
                    char flags_str[32] = "";
                    if (multicast->sid_bit || multicast->compression_bit) {
                        snprintf(flags_str, sizeof(flags_str), "SID:%d COMP:%d", 
                                multicast->sid_bit, multicast->compression_bit);
                    } else {
                        strcpy(flags_str, "None");
                    }
                    
                    // Try to find matching service from SLT
                    char service_id_str[16] = "";
                    char service_name_str[128] = "";
                    
                    // Search through SLT data to find matching service
                    for (int j = 0; j < g_lls_table_count; j++) {
                        if (g_lls_tables[j].type == TABLE_TYPE_SLT) {
                            SltData* slt_data = (SltData*)g_lls_tables[j].parsed_data;
                            ServiceInfo* slt_service = slt_data->head;
                            while (slt_service) {
                                // Check if destination IP:port matches
                                if (strcmp(slt_service->slsDestinationIpAddress, multicast->dest_ip_str) == 0 &&
                                    strcmp(slt_service->slsDestinationUdpPort, multicast->dest_port_str) == 0) {
                                    strncpy(service_id_str, slt_service->serviceId, sizeof(service_id_str) - 1);
                                    service_id_str[sizeof(service_id_str) - 1] = '\0';
                                    strncpy(service_name_str, slt_service->shortServiceName, sizeof(service_name_str) - 1);
                                    service_name_str[sizeof(service_name_str) - 1] = '\0';
                                    break;
                                }
                                slt_service = slt_service->next;
                            }
                            if (strlen(service_id_str) > 0) break; // Found a match, stop searching
                        }
                    }
                    
                    // If no match found, show placeholder
                    /*if (strlen(service_id_str) == 0) {
                        strcpy(service_id_str, "?");
                        strcpy(service_name_str, "Unknown");
                    }*/
                    
                    fprintf(f, "<tr><td>%d</td><td>%d.%d.%d.%d:%d</td><td>%s:%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
                        service->plp_id,
                        (multicast->src_ip >> 24) & 0xff, (multicast->src_ip >> 16) & 0xff,
                        (multicast->src_ip >> 8) & 0xff, multicast->src_ip & 0xff,
                        multicast->src_port,
                        multicast->dest_ip_str, multicast->dest_port_str,
                        service_id_str, service_name_str,
                        flags_str);
                    multicast = multicast->next;
                }
                service = service->next;
            }
            
            fprintf(f, "</tbody></table>");
            fprintf(f, "</div></details>\n");
        } 
    }
    if (lmt_count == 0) {
        // If LMT is not present, show the red message where the table would have been.
        fprintf(f, "<div class='details-content' style='margin-top: 1em; padding: 10px; border-radius: 5px; background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24;'>\n");
        fprintf(f, "<strong>Link Mapping Table Data Not Available</strong>\n");
        fprintf(f, "</div>\n");
    }

    // Check if CDT is present for later use
    /*int cdt_present = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_CDT) {
            cdt_present = 1;
            break;
        }
    }*/

    // --- Create a list of unique services found ---
    #define MAX_UNIQUE_SERVICES 1000
    ServiceInfo* unique_services[MAX_UNIQUE_SERVICES];
    int unique_service_count = 0;
    int udst_linked_flags[MAX_TABLES] = {0}; // Track linked UDSTs

    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            ServiceInfo* service = slt_data->head;
            while(service) {
                int service_found = 0;
                for (int j = 0; j < unique_service_count; j++) {
                    if (strcmp(unique_services[j]->serviceId, service->serviceId) == 0) {
                        service_found = 1;
                        break;
                    }
                }
                if (!service_found && unique_service_count < MAX_UNIQUE_SERVICES) {
                    unique_services[unique_service_count++] = service;
                }
                service = service->next;
            }
        }
    }

    // --- Service Summary Section (moved to top) ---
    if (unique_service_count > 0) {
        // Extract BSID from SLT data for the header
        char slt_bsid[16] = "";
        for (int i = 0; i < g_lls_table_count; i++) {
            if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
                SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
                if (strlen(slt_data->bsid) > 0) {
                    strncpy(slt_bsid, slt_data->bsid, sizeof(slt_bsid) - 1);
                    slt_bsid[sizeof(slt_bsid) - 1] = '\0';
                    break;
                }
            }
        }
        
        // Check if we have LMT data to show PLP column
        int show_plp_column = has_lmt_data();
        
        fprintf(f, "<h2>Service Summary");
        if (strlen(slt_bsid) > 0) {
            fprintf(f, " <span style='background:#ffff00;'>(SLT BSID: %s)</span>", slt_bsid);
        }
        fprintf(f, "</h2>\n");
        
        // Table header - conditionally include PLP column
        fprintf(f, "<table><thead><tr><th>Service Name</th><th>ID</th><th>Channel</th>");
        if (show_plp_column) {
            fprintf(f, "<th>PLP</th>");
        }
        fprintf(f, "<th>Protocol / Category</th><th>SLS Destination</th></tr></thead><tbody>\n");
        
        for(int i = 0; i < unique_service_count; i++) {
            ServiceInfo* service = unique_services[i];
            
            // Get protocol string
            const char* protocol_str = strcmp(service->slsProtocol, "1") == 0 ? "ROUTE" : (strcmp(service->slsProtocol, "2") == 0 ? "MMT" : service->slsProtocol);
            
            // Get category description
            const char* category_desc = "Unknown";
            int category_num = atoi(service->serviceCategory);
            switch(category_num) {
                case 1: category_desc = "Linear A/V Service"; break;
                case 2: category_desc = "Linear Audio Only Service"; break;
                case 3: category_desc = "App-Based Service"; break;
                case 4: category_desc = "ESG Service"; break;
                case 5: category_desc = "EAS Service"; break;
                case 6: category_desc = "DRM Data Service"; break;
            }
            
            // Format channel number (only show if both major and minor are present)
            char channel_str[32] = "";
            if (strlen(service->majorChannelNo) > 0 && strlen(service->minorChannelNo) > 0) {
                snprintf(channel_str, sizeof(channel_str), "%s.%s", service->majorChannelNo, service->minorChannelNo);
            }
            
            // Build service name with icons
            char service_name_with_icons[2048];
            snprintf(service_name_with_icons, sizeof(service_name_with_icons), "<a href=\"#service_%s\">%s</a>", service->serviceId, service->shortServiceName);
            
            if (service->protected) {
                strncat(service_name_with_icons, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:2px;'><path d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM15.1 8H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z' fill='#f57c00'/><title>Encrypted</title></svg>", sizeof(service_name_with_icons) - strlen(service_name_with_icons) - 1);
            }
            if (service->broadbandAccessRequired) {
                strncat(service_name_with_icons, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:2px;'><circle cx='12' cy='12' r='10' stroke='#1976d2' stroke-width='2' fill='none'/><ellipse cx='12' cy='12' rx='5' ry='10' stroke='#1976d2' stroke-width='1.5' fill='none'/><ellipse cx='12' cy='12' rx='10' ry='5' stroke='#1976d2' stroke-width='1.5' fill='none'/><line x1='2' y1='12' x2='22' y2='12' stroke='#1976d2' stroke-width='1.5'/><line x1='12' y1='2' x2='12' y2='22' stroke='#1976d2' stroke-width='1.5'/><title>Internet Required</title></svg>", sizeof(service_name_with_icons) - strlen(service_name_with_icons) - 1);
            }
            if (service->hidden) {
                strncat(service_name_with_icons, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:2px;'><path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z' fill='gray'/><line x1='4' y1='4' x2='20' y2='20' stroke='red' stroke-width='2'/><circle cx='12' cy='12' r='10' fill='none' stroke='red' stroke-width='2'/><title>Hidden</title></svg>", sizeof(service_name_with_icons) - strlen(service_name_with_icons) - 1);
            }
            
            // Get PLP information if LMT is available
            char plp_list[64] = "";
            if (show_plp_column) {
                get_plps_for_service_enhanced(service->slsDestinationIpAddress, service->slsDestinationUdpPort, plp_list, sizeof(plp_list));
                if (strlen(plp_list) == 0) {
                    strcpy(plp_list, "?"); // Unknown PLP mapping
                }
            }
            
            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td>", service_name_with_icons, service->serviceId, channel_str);
            
            // Conditionally add PLP column
            if (show_plp_column) {
                fprintf(f, "<td>%s</td>", plp_list);
            }
            
            fprintf(f, "<td>%s / %s</td><td>%s:%s</td></tr>\n",
                protocol_str, category_desc, service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        }
        fprintf(f, "</tbody></table>\n");
    }

    // --- Core Signaling Tables Section ---
    
    if (g_bps_data) {
        generate_bps_html_section(f, g_bps_data);
    }

    // CDT Table - Conditionally displayed based on presence
    generate_cdt_html_section(f, g_lls_table_count, g_lls_tables);
    
    // SLT Tables (raw XML only)
    int slt_instance_count = 0;
    int found_slt = 0;
    for (int i = 0; i < g_lls_table_count; i++) {
        if (g_lls_tables[i].type == TABLE_TYPE_SLT) {
            found_slt = 1;
            slt_instance_count++;
            //SltData* slt_data = (SltData*)g_lls_tables[i].parsed_data;
            fprintf(f, "<details><summary>Service List Table (SLT) Instance %d - Raw XML</summary>\n", slt_instance_count);
            fprintf(f, "<div class='details-content'><pre>"); // <h4>Raw XML</h4>
            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
            fprintf(f, "</pre></div></details>\n");
        }
    }
    if (!found_slt) {
        fprintf(f, "<details><summary>Service List Table (SLT) - Not Found</summary>\n");
        fprintf(f, "<div class='details-content'><p class='not-found'>No SLT tables found in this capture.</p></div></details>\n");
    }

    // --- Per-Service Details Section ---
    for (int i = 0; i < unique_service_count; i++) {
        ServiceInfo* service = unique_services[i];
        
        // Build service header with icons
        char service_header[4096];
        if (strlen(service->majorChannelNo) > 0 && strlen(service->minorChannelNo) > 0) {
            snprintf(service_header, sizeof(service_header), "Service %s: %s (%s.%s)", 
            service->serviceId, service->shortServiceName, service->majorChannelNo, service->minorChannelNo);
        } else {
            snprintf(service_header, sizeof(service_header), "Service %s: %s", 
            service->serviceId, service->shortServiceName);
        }
        
        if (service->protected) {
            strncat(service_header, " <svg width='20' height='20' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><path d='M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM12 17c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM15.1 8H8.9V6c0-1.71 1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z' fill='#f57c00'/><title>Encrypted</title></svg>", sizeof(service_header) - strlen(service_header) - 1);
        }
        if (service->broadbandAccessRequired) {
            strncat(service_header, " <svg width='20' height='20' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><circle cx='12' cy='12' r='10' stroke='#1976d2' stroke-width='2' fill='none'/><ellipse cx='12' cy='12' rx='5' ry='10' stroke='#1976d2' stroke-width='1.5' fill='none'/><ellipse cx='12' cy='12' rx='10' ry='5' stroke='#1976d2' stroke-width='1.5' fill='none'/><line x1='2' y1='12' x2='22' y2='12' stroke='#1976d2' stroke-width='1.5'/><line x1='12' y1='2' x2='12' y2='22' stroke='#1976d2' stroke-width='1.5'/><title>Internet Required</title></svg>", sizeof(service_header) - strlen(service_header) - 1);
        }
        if (service->hidden) {
            strncat(service_header, " <svg width='20' height='20' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><path d='M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z' fill='gray'/><line x1='4' y1='4' x2='20' y2='20' stroke='red' stroke-width='2'/><circle cx='12' cy='12' r='10' fill='none' stroke='red' stroke-width='2'/><title>Hidden</title></svg>", sizeof(service_header) - strlen(service_header) - 1);
        }
        
        fprintf(f, "<h2 id=\"service_%s\">%s</h2>\n", service->serviceId, service_header);
        
        fprintf(f, "<div class='service-container'>\n");

        // NEW: Enhanced Service Summary Section
        fprintf(f, "<div class='service-summary' style='background-color: #e3f2fd; border: 1px solid #2196f3; padding: 15px; border-radius: 8px; margin-bottom: 15px;'>\n");
        fprintf(f, "<div style='display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px;'>\n");
        
        // Basic service info
        const char* summary_category_desc = "Unknown";
        int summary_category_num = atoi(service->serviceCategory);
        switch(summary_category_num) {
            case 1: summary_category_desc = "Linear A/V Service"; break;
            case 2: summary_category_desc = "Linear Audio Only Service"; break;
            case 3: summary_category_desc = "App-Based Service"; break;
            case 4: summary_category_desc = "ESG Service"; break;
            case 5: summary_category_desc = "EAS Service"; break;
            case 6: summary_category_desc = "DRM Data Service"; break;
        }
        const char* summary_protocol_str = strcmp(service->slsProtocol, "1") == 0 ? "ROUTE" : (strcmp(service->slsProtocol, "2") == 0 ? "MMT" : service->slsProtocol);
        
        fprintf(f, "<div><strong>Protocol:</strong> %s<br />\n", summary_protocol_str);
        fprintf(f, "<strong>Category:</strong> %s</div>\n", summary_category_desc);
        fprintf(f, "<div><strong>Source:</strong> %s<br />\n", service->slsSourceIpAddress);
        fprintf(f, "<strong>Destination:</strong> %s:%s</div>\n", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        
        // Check for MPD data to show video/audio info (using highest resolution)
        MpdData* service_mpd = NULL;
        for (int j = 0; j < g_lls_table_count; j++) {
            if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                g_lls_tables[j].type == TABLE_TYPE_MPD) {
                service_mpd = (MpdData*)g_lls_tables[j].parsed_data;
                break;
            }
        }
        
        if (service_mpd) {
            // Find video and audio info (prefer highest resolution for video, most channels for audio)
            MpdAdaptationSet* as = service_mpd->head_as;
            int found_video = 0, found_audio = 0;
            int max_audio_channels = 0;
            MpdRepresentation* best_audio_rep = NULL;
            int total_audio_streams = 0;
            
            // First pass: count audio streams and find the best one
            as = service_mpd->head_as;
            while (as) {
                if (strcmp(as->contentType, "audio") == 0 || strcmp(as->mimeType, "audio/mp4") == 0) {
                    total_audio_streams++;
                    MpdRepresentation* rep = as->head_rep;
                    while (rep) {
                        int channels = 0;
                        if (strlen(rep->audioChannelCount) > 0) {
                            channels = atoi(rep->audioChannelCount);
                            if (channels > max_audio_channels) {
                                max_audio_channels = channels;
                                best_audio_rep = rep;
                            }
                        }
                        rep = rep->next;
                    }
                }
                as = as->next;
            }
            
            // Second pass: display video and best audio
            as = service_mpd->head_as;
            while (as && (!found_video || !found_audio)) {
                if ((strcmp(as->contentType, "video") == 0 || strcmp(as->mimeType, "video/mp4") == 0) && !found_video) {
                    // Find the highest resolution representation
                    MpdRepresentation* rep = find_highest_resolution_video(as);
                    if (rep && strlen(rep->width) > 0 && strlen(rep->height) > 0) {
                        fprintf(f, "<div><strong>Video:</strong> %sx%s", rep->width, rep->height);
                        if (strlen(rep->scanType) > 0) {
                            fprintf(f, "%c", (strcmp(rep->scanType, "progressive") == 0) ? 'p' : 'i');
                        }
                        if (strlen(rep->frameRate) > 0) {
                            // Parse fractional frame rates like "60000/1001"
                            if (strchr(rep->frameRate, '/')) {
                                char* slash = strchr(rep->frameRate, '/');
                                int numerator = atoi(rep->frameRate);
                                int denominator = atoi(slash + 1);
                                if (denominator > 0) {
                                    double fps = (double)numerator / denominator;
                                    fprintf(f, " (%.2f fps)", fps);
                                }
                            } else {
                                fprintf(f, " (%s fps)", rep->frameRate);
                            }
                        }
                        if (strlen(rep->codecs) > 0) {
                            fprintf(f, "<br />\n<strong>Codec:</strong> %s", rep->codecs);
                        }
                        fprintf(f, "</div>\n");
                        found_video = 1;
                    }
                } else if ((strcmp(as->contentType, "audio") == 0 || strcmp(as->mimeType, "audio/mp4") == 0) && !found_audio) {
                    // Use the best audio representation we found
                    if (best_audio_rep) {
                        fprintf(f, "<div><strong>Audio:</strong> ");
                        if (strlen(best_audio_rep->audioChannelCount) > 0) {
                            fprintf(f, "%s ch", best_audio_rep->audioChannelCount);
                        }
                        if (strlen(best_audio_rep->bandwidth) > 0) {
                            if (strlen(best_audio_rep->audioChannelCount) > 0) fprintf(f, " @ ");
                            char formatted_bandwidth[32];
                            format_bandwidth(best_audio_rep->bandwidth, formatted_bandwidth, sizeof(formatted_bandwidth));
                            fprintf(f, "%s", formatted_bandwidth);
                        }
                        
                        // Add green plus sign if there are additional audio streams
                        if (total_audio_streams > 1) {
                            fprintf(f, " <svg width='16' height='16' viewBox='0 0 24 24' fill='none' style='display:inline;vertical-align:middle;margin-left:4px;'><circle cx='12' cy='12' r='10' fill='#4CAF50'/><path d='M12 6v12M6 12h12' stroke='white' stroke-width='2' stroke-linecap='round'/><title>+%d additional audio stream%s</title></svg>", 
                                   total_audio_streams - 1, 
                                   (total_audio_streams - 1) == 1 ? "" : "s");
                        }
                        
                        if (strlen(best_audio_rep->codecs) > 0) {
                            fprintf(f, "<br />\n<strong>Codec:</strong> %s", best_audio_rep->codecs);
                        }
                        fprintf(f, "</div>\n");
                        found_audio = 1;
                    }
                }
                as = as->next;
            }
        } else if (strcmp(service->slsProtocol, "2") == 0) {
            // MMT service - look for cached parameters
            int found_video = 0, found_audio = 0;
            
            // Find video and audio packet IDs from MPT
            for (int j = 0; j < g_lls_table_count; j++) {
                if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                    strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                    g_lls_tables[j].type == TABLE_TYPE_MP_TABLE_BINARY) {
                    
                    ProprietaryMptData* mpt_data = (ProprietaryMptData*)g_lls_tables[j].parsed_data;
                    ProprietaryMptAsset* asset = mpt_data->assets;
                    
                    while (asset && (!found_video || !found_audio)) {
                        if (strcmp(asset->asset_type, "video") == 0 && !found_video) {
                            MmtMediaParams* params = get_cached_mmt_params(service->slsDestinationIpAddress,
                                                                           service->slsDestinationUdpPort,
                                                                           asset->packet_id);
                            if (params && strlen(params->resolution) > 0) {
                                fprintf(f, "<div><strong>Video:</strong> %s", params->resolution);
                                if (strlen(params->scan_type) > 0) {
                                    fprintf(f, "%c", (strcmp(params->scan_type, "progressive") == 0) ? 'p' : 'i');
                                }
                                if (strlen(params->frame_rate) > 0) {
                                    fprintf(f, " (%.2f fps)", atof(params->frame_rate));
                                }
                                if (strlen(params->video_codec) > 0) {
                                    fprintf(f, "<br />\n<strong>Codec:</strong> %s", params->video_codec);
                                }
                                fprintf(f, "</div>\n");
                                found_video = 1;
                            }
                        } else if (strcmp(asset->asset_type, "audio") == 0 && !found_audio) {
                            MmtMediaParams* params = get_cached_mmt_params(service->slsDestinationIpAddress,
                                                                           service->slsDestinationUdpPort,
                                                                           asset->packet_id);
                            if (params && strlen(params->audio_codec) > 0) {
                                fprintf(f, "<div><strong>Audio:</strong> ");
                                if (strlen(params->audio_channels) > 0) {
                                    fprintf(f, "%s ch ", params->audio_channels);
                                }
                                fprintf(f, "<br />\n<strong>Codec:</strong> %s</div>\n", params->audio_codec);
                                found_audio = 1;
                            }
                        }
                        asset = asset->next;
                    }
                    break;
                }
            }
        }
        
        fprintf(f, "<div><strong>Hidden:</strong> ");
        if (service->hidden || service->hideInGuide) {
            if (service->hidden && service->hideInGuide) {
                fprintf(f, "Service & Guide");
            } else if (service->hidden) {
                fprintf(f, "Service");
            } else {
                fprintf(f, "Guide");
            }
        } else {
            fprintf(f, "No");
        }
        fprintf(f, "<br />\n");
        
        // Check for HELD data for this service
        HeldData* service_held = NULL;
        for (int j = 0; j < g_lls_table_count; j++) {
            if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) == 0 &&
                strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) == 0 &&
                g_lls_tables[j].type == TABLE_TYPE_HELD) {
                service_held = (HeldData*)g_lls_tables[j].parsed_data;
                break;
            }
        }
        
        const char* app_type = determine_app_type(service_held);
        fprintf(f, "<strong>App:</strong> %s</div>\n", app_type);
        
        fprintf(f, "</div></div>\n"); // Close summary section
        
        //fprintf(f, "<div class='service-container'>\n");

        // Print SLT info for this service
        fprintf(f, "<details><summary>Service Details (from SLT)</summary>\n<div class='details-content'>\n");
        const char* category_desc = "Unknown";
        int category_num = atoi(service->serviceCategory);
        switch(category_num) {
            case 1: category_desc = "Linear A/V Service"; break;
            case 2: category_desc = "Linear Audio Only Service"; break;
            case 3: category_desc = "App-Based Service"; break;
            case 4: category_desc = "ESG Service"; break;
            case 5: category_desc = "EAS Service"; break;
            case 6: category_desc = "DRM Data Service"; break;
        }
        const char* protocol_str = strcmp(service->slsProtocol, "1") == 0 ? "ROUTE" : (strcmp(service->slsProtocol, "2") == 0 ? "MMT" : service->slsProtocol);
        fprintf(f, "<ul>\n");
        fprintf(f, "<li><strong>Global Service ID:</strong> %s</li>\n", service->globalServiceID);
        fprintf(f, "<li><strong>Category:</strong> %s (%s)</li>\n", service->serviceCategory, category_desc);
        fprintf(f, "<li><strong>SLS Destination:</strong> %s:%s</li>\n", service->slsDestinationIpAddress, service->slsDestinationUdpPort);
        fprintf(f, "<li><strong>SLS Source:</strong> %s</li>\n", service->slsSourceIpAddress);
        fprintf(f, "<li><strong>SLS Protocol Version:</strong> %s.%s (%s)</li>\n", service->slsMajorProtocolVersion, service->slsMinorProtocolVersion, protocol_str);
        if (service->protected) fprintf(f, "<li><strong>Protected:</strong> Yes</li>\n");
        if (service->broadbandAccessRequired) fprintf(f, "<li><strong>Broadband Required:</strong> Yes</li>\n");
        if (service->hidden) fprintf(f, "<li><strong>Hidden:</strong> Yes</li>\n");
        if (service->hideInGuide) fprintf(f, "<li><strong>Hide in Guide:</strong> Yes</li>\n");
        fprintf(f, "</ul>\n");
        fprintf(f, "</div></details>\n");

        // Print associated tables for this service (MPD, HELD, ESG)
        int found_items_for_service = 0;
        int fdt_count = 0;
        int mpd_count = 0;
        int stsid_count = 0;
        int usd_route_count = 0;
        int usd_mmt_count = 0;
        int service_signaling_count = 0;
        int mp_table_xml_count = 0;
        int mp_table_binary_count = 0;
        int held_count = 0;
        int esg_count = 0;
        int dwd_count = 0;
        

        // Define the desired display order
        TableType display_order[] = {
            TABLE_TYPE_USER_SERVICE_DESCRIPTION,     // 3. USD ROUTE
            TABLE_TYPE_USBD,                          // 3. USBD
            TABLE_TYPE_USD,                           // 4. USD 
            TABLE_TYPE_STSID,                 // 2. S-TSID (stream descriptions)
            TABLE_TYPE_MP_TABLE_XML,                  // 6. MMT MP Table XML
            TABLE_TYPE_MP_TABLE_BINARY,               // 7. MMT MP Table Binary
            TABLE_TYPE_SERVICE_SIGNALING,             // 5. Service Signaling
            TABLE_TYPE_MPD,                    // 1. MPD (most important for media info)
            TABLE_TYPE_HELD,                          // 8. HELD
            TABLE_TYPE_ESG_FRAGMENT,                  // 9. ESG
            TABLE_TYPE_DWD                            // 10. DWD
        };
        int num_types = sizeof(display_order) / sizeof(display_order[0]);

        // Process tables in the specified order
        for (int order_idx = 0; order_idx < num_types; order_idx++) {
            TableType current_type = display_order[order_idx];
            
            // Find all tables of this type for this service
            for (int j = 0; j < g_lls_table_count; j++) {
                if (g_lls_tables[j].type != current_type) continue;
                if (strcmp(g_lls_tables[j].destinationIp, service->slsDestinationIpAddress) != 0) continue;
                if (strcmp(g_lls_tables[j].destinationPort, service->slsDestinationUdpPort) != 0) continue;

                found_items_for_service = 1;

                switch (current_type) {
                    case TABLE_TYPE_FDT: {
                        fdt_count++;
                        FDTInstanceData* fdt_data = (FDTInstanceData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>File Description Table (FDT) Instance %d (Expires: %s)</summary>\n", fdt_count, fdt_data->expires);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Location</th><th>TOI</th><th>Content Length</th><th>Content Type</th></tr></thead>\n<tbody>\n");
                        FDTFileInfo* file = fdt_data->head;
                        while(file) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", file->contentLocation, file->toi, file->contentLength, file->contentType);
                            file = file->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_MPD: {
                        mpd_count++;
                        MpdData* mpd_data = (MpdData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>Media Presentation Description (MPD) Instance %d (Published: %s)</summary>\n", mpd_count, mpd_data->publishTime);
                        fprintf(f, "<div class='details-content'><div class='mpd-summary'>");
                        fprintf(f, "<strong>Type:</strong> %s<br>\n", mpd_data->type);
                        fprintf(f, "<strong>Min Buffer Time:</strong> %s<br>\n", mpd_data->minBufferTime);
                        fprintf(f, "<strong>Profiles:</strong> %s\n</div>\n", mpd_data->profiles);
                        
                        MpdAdaptationSet* as = mpd_data->head_as;
                        while(as) {
                            fprintf(f, "<h4>Adaptation Set (Content: %s, Mime: %s", as->contentType, as->mimeType);
                            if(strlen(as->lang) > 0) fprintf(f, ", Lang: %s", as->lang);
                            if(strlen(as->par) > 0) fprintf(f, ", PAR: %s", as->par);
                            fprintf(f, ")</h4>\n");
                            
                            // Debug: Let's also check AdaptationSet level attributes
                            /*fprintf(f, "<div style='background-color: #f0f0f0; padding: 5px; margin: 5px 0; font-size: 12px;'>");
                            fprintf(f, "<strong>Debug - AdaptationSet attributes:</strong> ");
                            fprintf(f, "contentType='%s' mimeType='%s' lang='%s' par='%s'", 
                                as->contentType, as->mimeType, as->lang, as->par);
                            fprintf(f, "</div>");*/
                            
                            MpdRepresentation* rep = as->head_rep;
                            while(rep) {
                                fprintf(f, "<h5>Representation ID: %s</h5><ul>\n", rep->id);
                                
                                // Debug: Show all parsed attributes
                                /*fprintf(f, "<li><strong>Debug - All parsed attributes:</strong><br>\n");
                                fprintf(f, "id='%s' codecs='%s' bandwidth='%s'<br>\n", rep->id, rep->codecs, rep->bandwidth);
                                fprintf(f, "width='%s' height='%s' frameRate='%s'<br>\n", rep->width, rep->height, rep->frameRate);
                                fprintf(f, "audioSamplingRate='%s' audioChannelCount='%s'<br>\n", rep->audioSamplingRate, rep->audioChannelCount);
                                fprintf(f, "sar='%s' scanType='%s' displayAspectRatio='%s'</li>\n", rep->sar, rep->scanType, rep->displayAspectRatio);*/
                                
                                fprintf(f, "<li><strong>Bandwidth:</strong> %s", rep->bandwidth);
                                if(strlen(rep->bandwidth) > 0) {
                                    int bw = atoi(rep->bandwidth);
                                    if(bw > 1000000) {
                                        fprintf(f, " (%.1f Mbps)", bw / 1000000.0);
                                    } else if(bw > 1000) {
                                        fprintf(f, " (%.0f kbps)", bw / 1000.0);
                                    }
                                }
                                fprintf(f, "</li>\n");
                                
                                fprintf(f, "<li><strong>Codecs:</strong> %s</li>\n", rep->codecs);
                                
                                if(strlen(rep->width) > 0 && strlen(rep->height) > 0) {
                                    fprintf(f, "<li><strong>Resolution:</strong> %sx%s", rep->width, rep->height);
                                    if(strlen(rep->displayAspectRatio) > 0) {
                                        fprintf(f, " (%s)", rep->displayAspectRatio);
                                    }
                                    fprintf(f, "</li>\n");
                                }
                                
                                if(strlen(rep->frameRate) > 0) {
                                    fprintf(f, "<li><strong>Frame Rate:</strong> %s", rep->frameRate);
                                    // Parse fractional frame rates like "60000/1001"
                                    if(strchr(rep->frameRate, '/')) {
                                        char* slash = strchr(rep->frameRate, '/');
                                        int numerator = atoi(rep->frameRate);
                                        int denominator = atoi(slash + 1);
                                        if(denominator > 0) {
                                            double fps = (double)numerator / denominator;
                                            fprintf(f, " (%.2f fps)", fps);
                                        }
                                    }
                                    fprintf(f, "</li>\n");
                                }
                                
                                if(strlen(rep->scanType) > 0) fprintf(f, "<li><strong>Scan Type:</strong> %s</li>\n", rep->scanType);
                                if(strlen(rep->sar) > 0) fprintf(f, "<li><strong>Sample Aspect Ratio:</strong> %s</li>\n", rep->sar);
                                if(strlen(rep->audioSamplingRate) > 0) fprintf(f, "<li><strong>Audio Sample Rate:</strong> %s Hz</li>\n", rep->audioSamplingRate);
                                if(strlen(rep->audioChannelCount) > 0) fprintf(f, "<li><strong>Audio Channels:</strong> %s</li>\n", rep->audioChannelCount);
                                
                                fprintf(f, "<li><strong>Segment Template:</strong>");
                                if(rep->segmentTemplate.timeline) {
                                    fprintf(f, "<ul class='segment-list'><li><strong>Timescale:</strong> %s</li>\n", rep->segmentTemplate.timescale);
                                    SegmentTimelineS* s = rep->segmentTemplate.timeline;
                                    while(s) {
                                        fprintf(f, "<li><strong>S: t=</strong>%s, <strong>d=</strong>%s, <strong>r=</strong>%s</li>", s->t, s->d, strlen(s->r) > 0 ? s->r : "0");
                                        s = s->next;
                                    }
                                    fprintf(f, "</ul>");

                                } else {
                                    fprintf(f, "<ul class='segment-list'>\n");
                                    fprintf(f, "<li><strong>Initialization:</strong> %s</li>\n", rep->segmentTemplate.initialization);
                                    fprintf(f, "<li><strong>Media URL:</strong> %s</li>\n", rep->segmentTemplate.media);
                                    fprintf(f, "<li><strong>Timescale:</strong> %s, <strong>Duration:</strong> %s, <strong>Start:</strong> %s</li>\n", rep->segmentTemplate.timescale, rep->segmentTemplate.duration, rep->segmentTemplate.startNumber);
                                    fprintf(f, "</ul>");
                                }
                                if (rep->drmInfo) {
                                    fprintf(f, "<li><strong>DRM Protection:</strong><ul style='margin: 5px 0; padding-left: 20px;'>");
                                    DrmInfo* drm = rep->drmInfo;
                                    while (drm) {
                                        fprintf(f, "<li><strong>System:</strong> %s", drm->systemName);
                                        if (strlen(drm->contentId) > 0) {
                                            fprintf(f, " | <strong>Content ID:</strong> %s", drm->contentId);
                                        }
                                        if (strlen(drm->licenseUrl) > 0) {
                                            fprintf(f, "<br><strong>License URL:</strong> <a href='%s' target='_blank'>%s</a>", drm->licenseUrl, drm->licenseUrl);
                                        }
                                        if (strlen(drm->groupLicenseUrl) > 0) {
                                            fprintf(f, "<br><strong>Group License:</strong> %s", drm->groupLicenseUrl);
                                        }
                                        fprintf(f, "</li>");
                                        drm = drm->next;
                                    }
                                    fprintf(f, "</ul></li>");
                                } fprintf(f, "</li></ul>\n");

                                rep = rep->next;
                            }
                            as = as->next;
                        }
                        fprintf(f, "<h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_HELD: {
                        held_count++;
                        HeldData* held_data = (HeldData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>HTML Entry-point Description (HELD) Instance %d</summary>\n", held_count);
                        fprintf(f, "<div class='details-content'><ul>\n");
                        if(strlen(held_data->bbandEntryPageUrl) > 0) fprintf(f, "<li><strong>Broadband Entry Page:</strong> <a href='%s' target='_blank'>%s</a></li>\n", held_data->bbandEntryPageUrl, held_data->bbandEntryPageUrl);
                        if(strlen(held_data->clearBbandEntryPageUrl) > 0) fprintf(f, "<li><strong>Clear Broadband Entry Page:</strong> <a href='%s' target='_blank'>%s</a></li>\n", held_data->clearBbandEntryPageUrl, held_data->clearBbandEntryPageUrl);
                        if(strlen(held_data->coupledServices) > 0) fprintf(f, "<li><strong>Coupled Services:</strong> %s</li>\n", held_data->coupledServices);
                        fprintf(f, "</ul><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_ESG_FRAGMENT: {
                        // Only process ESG fragments once per service (on first encounter)
                        if (esg_count > 0) {
                            continue;
                        }
                        
                        // First, check if there's an SGDD for this service
                        SgddData* sgdd = NULL;
                        for (int sgdd_idx = 0; sgdd_idx < g_lls_table_count; sgdd_idx++) {
                            if (g_lls_tables[sgdd_idx].type == TABLE_TYPE_SGDD) {
                                SgddData* temp_sgdd = (SgddData*)g_lls_tables[sgdd_idx].parsed_data;
                                if (temp_sgdd && temp_sgdd->entries) {
                                    // Check if any entry matches this service's IP:Port
                                    SgddEntry* entry = temp_sgdd->entries;
                                    while (entry) {
                                        if (strcmp(entry->ipAddress, service->slsDestinationIpAddress) == 0 &&
                                            strcmp(entry->port, service->slsDestinationUdpPort) == 0) {
                                            sgdd = temp_sgdd;
                                            break;
                                        }
                                        entry = entry->next;
                                    }
                                }
                                if (sgdd) break;
                            }
                        }
                        
                        // Collect and merge ALL ESG fragments for this service
                        EsgServiceInfo* merged_services = NULL;
                        EsgProgramInfo* merged_programs = NULL;
                        int fragment_count = 0;
                        
                        // Store raw XML by service
                        typedef struct {
                            char service_id[256];
                            char** xmls;
                            int xml_count;
                        } ServiceXml;
                        ServiceXml* service_xmls = malloc(sizeof(ServiceXml) * 100);
                        int service_xml_count = 0;
                        
                        for (int k = 0; k < g_lls_table_count; k++) {
                            if (g_lls_tables[k].type != TABLE_TYPE_ESG_FRAGMENT) continue;
                            if (strcmp(g_lls_tables[k].destinationIp, service->slsDestinationIpAddress) != 0) continue;
                            if (strcmp(g_lls_tables[k].destinationPort, service->slsDestinationUdpPort) != 0) continue;
                            
                            fragment_count++;
                            
                            EsgFragmentData* frag = (EsgFragmentData*)g_lls_tables[k].parsed_data;
                            if (!frag) continue;
                            
                            // Merge services (deduplicate by ID)
                            EsgServiceInfo* svc = frag->services;
                            while (svc) {
                                EsgServiceInfo* existing = merged_services;
                                int found = 0;
                                while (existing) {
                                    if (strcmp(existing->id, svc->id) == 0) {
                                        found = 1;
                                        if (strlen(existing->name) == 0 && strlen(svc->name) > 0) {
                                            strncpy(existing->name, svc->name, sizeof(existing->name)-1);
                                        }
                                        if (strlen(existing->description) == 0 && strlen(svc->description) > 0) {
                                            strncpy(existing->description, svc->description, sizeof(existing->description)-1);
                                        }
                                        if (strlen(existing->majorChannel) == 0 && strlen(svc->majorChannel) > 0) {
                                            strncpy(existing->majorChannel, svc->majorChannel, sizeof(existing->majorChannel)-1);
                                        }
                                        if (strlen(existing->minorChannel) == 0 && strlen(svc->minorChannel) > 0) {
                                            strncpy(existing->minorChannel, svc->minorChannel, sizeof(existing->minorChannel)-1);
                                        }
                                        if (!existing->icons && svc->icons) {
                                            existing->icons = svc->icons;
                                        }
                                        if (!existing->schedule && svc->schedule) {
                                            existing->schedule = svc->schedule;
                                        }
                                        break;
                                    }
                                    existing = existing->next;
                                }
                                
                                if (!found) {
                                    EsgServiceInfo* copy = calloc(1, sizeof(EsgServiceInfo));
                                    memcpy(copy, svc, sizeof(EsgServiceInfo));
                                    copy->icons = svc->icons;
                                    copy->schedule = svc->schedule;
                                    copy->next = merged_services;
                                    merged_services = copy;
                                    
                                    // Initialize XML storage for this service
                                    ServiceXml* sx = &service_xmls[service_xml_count++];
                                    strncpy(sx->service_id, svc->id, sizeof(sx->service_id)-1);
                                    sx->xmls = malloc(sizeof(char*) * 500);
                                    sx->xml_count = 0;
                                }
                                svc = svc->next;
                            }
                            
                            // Merge programs and associate XML with service
                            EsgProgramInfo* prog = frag->programs;
                            while (prog) {
                                // Determine which service this program belongs to
                                char service_num[32] = "";
                                const char* content_marker = strstr(prog->id, "Content-");
                                if (content_marker) {
                                    const char* dash = strchr(content_marker + 8, '-');
                                    if (dash) {
                                        size_t len = dash - (content_marker + 8);
                                        if (len < sizeof(service_num)) {
                                            strncpy(service_num, content_marker + 8, len);
                                            service_num[len] = '\0';
                                        }
                                    }
                                }
                                
                                // Store XML under appropriate service
                                if (strlen(service_num) > 0) {
                                    char service_id_pattern[256];
                                    snprintf(service_id_pattern, sizeof(service_id_pattern), "Service-%s", service_num);
                                    for (int sx_idx = 0; sx_idx < service_xml_count; sx_idx++) {
                                        if (strstr(service_xmls[sx_idx].service_id, service_id_pattern)) {
                                            service_xmls[sx_idx].xmls[service_xmls[sx_idx].xml_count++] = g_lls_tables[k].content_id;
                                            break;
                                        }
                                    }
                                }
                                
                                EsgProgramInfo* existing = merged_programs;
                                int found = 0;
                                while (existing) {
                                    if (strcmp(existing->id, prog->id) == 0) {
                                        found = 1;
                                        if (strlen(existing->title) == 0 && strlen(prog->title) > 0) {
                                            strncpy(existing->title, prog->title, sizeof(existing->title)-1);
                                        }
                                        if (strlen(existing->description) == 0 && strlen(prog->description) > 0) {
                                            strncpy(existing->description, prog->description, sizeof(existing->description)-1);
                                        }
                                        if (!existing->icons && prog->icons) {
                                            existing->icons = prog->icons;
                                        }
                                        if (!existing->ratings && prog->ratings) {
                                            existing->ratings = prog->ratings;
                                        }
                                        break;
                                    }
                                    existing = existing->next;
                                }
                                
                                if (!found) {
                                    EsgProgramInfo* copy = calloc(1, sizeof(EsgProgramInfo));
                                    memcpy(copy, prog, sizeof(EsgProgramInfo));
                                    copy->icons = prog->icons;
                                    copy->ratings = prog->ratings;
                                    copy->next = merged_programs;
                                    merged_programs = copy;
                                }
                                prog = prog->next;
                            }
                        }
                        
                        if (fragment_count == 0) {
                            free(service_xmls);
                            continue;
                        }
                        
                        esg_count = 1;
                        found_items_for_service = 1;
                        
                        // Sort services by service number
                        EsgServiceInfo** service_array = malloc(sizeof(EsgServiceInfo*) * 100);
                        int svc_count = 0;
                        EsgServiceInfo* svc = merged_services;
                        while(svc) {
                            service_array[svc_count++] = svc;
                            svc = svc->next;
                        }
                        
                        // Bubble sort by service number
                        for (int a = 0; a < svc_count - 1; a++) {
                            for (int b = 0; b < svc_count - a - 1; b++) {
                                int num1 = 9999, num2 = 9999;
                                const char* s1 = strstr(service_array[b]->id, "Service-");
                                const char* s2 = strstr(service_array[b+1]->id, "Service-");
                                if (s1) num1 = atoi(s1 + 8);
                                if (s2) num2 = atoi(s2 + 8);
                                if (num1 > num2) {
                                    EsgServiceInfo* temp = service_array[b];
                                    service_array[b] = service_array[b+1];
                                    service_array[b+1] = temp;
                                }
                            }
                        }
                        
                        int service_count = svc_count;
                        int program_count = count_programs(merged_programs);
                        
                        fprintf(f, "<details><summary>Electronic Service Guide (ESG) - %d Service(s), %d Program(s) (from %d fragments)</summary>\n", 
                                service_count, program_count, fragment_count);
                        fprintf(f, "<div class='details-content'>\n");
                        
                        // Show SGDD metadata first if available
                        if (sgdd) {
                            fprintf(f, "<details><summary><strong>📋 Guide Delivery Information (SGDD Version %s)</strong></summary>\n", sgdd->version);
                            fprintf(f, "<div style='margin-left: 20px;'>");
                            
                            SgddEntry* entry = sgdd->entries;
                            while (entry) {
                                // Convert timestamps
                                time_t start_ts = atoll(entry->startTime);
                                time_t end_ts = atoll(entry->endTime);
                                struct tm* tm_start = localtime(&start_ts);
                                struct tm* tm_end = localtime(&end_ts);
                                char start_str[64], end_str[64];
                                strftime(start_str, sizeof(start_str), "%Y-%m-%d %H:%M", tm_start);
                                strftime(end_str, sizeof(end_str), "%Y-%m-%d %H:%M", tm_end);
                                
                                fprintf(f, "<h4>Coverage: %s to %s</h4>", start_str, end_str);
                                fprintf(f, "<p><strong>Service:</strong> %s</p>", entry->serviceCriteria);
                                
                                SgddDeliveryUnit* unit = entry->deliveryUnits;
                                while (unit) {
                                    fprintf(f, "<details><summary>Delivery Unit: %s (TOI %s)</summary>", 
                                            unit->contentLocation, unit->transportObjectId);
                                    fprintf(f, "<table style='margin: 10px;'><tr><th>Transport ID</th><th>Fragment ID</th><th>Type</th></tr>");
                                    
                                    SgddFragment* frag_sgdd = unit->fragments;
                                    while (frag_sgdd) {
                                        const char* type_desc = "Unknown";
                                        if (strcmp(frag_sgdd->fragmentType, "1") == 0) type_desc = "Service";
                                        else if (strcmp(frag_sgdd->fragmentType, "2") == 0) type_desc = "Content/Program";
                                        else if (strcmp(frag_sgdd->fragmentType, "3") == 0) type_desc = "Schedule";
                                        
                                        fprintf(f, "<tr><td>%s</td><td><small>%s</small></td><td>%s</td></tr>",
                                                frag_sgdd->transportId, frag_sgdd->fragmentId, type_desc);
                                        frag_sgdd = frag_sgdd->next;
                                    }
                                    fprintf(f, "</table></details>");
                                    unit = unit->next;
                                }
                                
                                entry = entry->next;
                            }
                            
                            fprintf(f, "</div></details><br>\n");
                        }
                        
                        // Display services in order
                        for (int svc_idx = 0; svc_idx < svc_count; svc_idx++) {
                            EsgServiceInfo* esg_service = service_array[svc_idx];
                            
                            // Extract service number
                            char service_num[32] = "";
                            const char* service_marker = strstr(esg_service->id, "Service-");
                            if (service_marker) {
                                strncpy(service_num, service_marker + 8, sizeof(service_num) - 1);
                            }
                            
                            fprintf(f, "<details><summary><strong>Service %s: %s", 
                                    service_num, 
                                    strlen(esg_service->name) > 0 ? esg_service->name : esg_service->id);
                                    
                            if (strlen(esg_service->majorChannel) > 0 && strlen(esg_service->minorChannel) > 0) {
                                fprintf(f, " (%s.%s)", esg_service->majorChannel, esg_service->minorChannel);
                            }
                            fprintf(f, "</strong></summary>\n");
                            fprintf(f, "<div style='margin-left: 20px;'>\n");
                            
                            fprintf(f, "<table><tr><th>Field</th><th>Value</th></tr>");
                            fprintf(f, "<tr><td><strong>ID</strong></td><td>%s</td></tr>", esg_service->id);
                            if(strlen(esg_service->serviceStatus) > 0)
                                fprintf(f, "<tr><td><strong>Status</strong></td><td>%s</td></tr>", esg_service->serviceStatus);
                            if(strlen(esg_service->genre) > 0) 
                                fprintf(f, "<tr><td><strong>Genre</strong></td><td>%s</td></tr>", esg_service->genre);
                            if(strlen(esg_service->description) > 0) 
                                fprintf(f, "<tr><td><strong>Description</strong></td><td>%s</td></tr>", esg_service->description);
                            fprintf(f, "</table>");
                            
                            // Display service icons if present
                            if(esg_service->icons) {
                                fprintf(f, "<h5>Service Icons:</h5>");
                                fprintf(f, "<div style='display: flex; gap: 10px; flex-wrap: wrap;'>");
                                EsgMediaAsset* icon = esg_service->icons;
                                while(icon) {
                                    fprintf(f, "<div style='border: 1px solid #ddd; padding: 5px;'>");
                                    fprintf(f, "<img src='%s' alt='Service icon' style='max-width: 150px; max-height: 150px; display: block;' onerror=\"this.style.display='none'; this.nextElementSibling.style.display='block';\">", icon->uri);
                                    fprintf(f, "<div style='display: none; color: red;'>Image failed to load</div>");
                                    fprintf(f, "<small>%s<br>%sx%s</small>", icon->contentType, 
                                            strlen(icon->width) > 0 ? icon->width : "?", 
                                            strlen(icon->height) > 0 ? icon->height : "?");
                                    fprintf(f, "</div>");
                                    icon = icon->next;
                                }
                                fprintf(f, "</div>");
                            }
                            
                            // Collect schedule events with timestamps for sorting
                            typedef struct {
                                EsgScheduleEvent* event;
                                EsgProgramInfo* program;
                                time_t timestamp;
                            } ScheduleItem;
                            
                            ScheduleItem* schedule_items = malloc(sizeof(ScheduleItem) * 1000);
                            int schedule_count = 0;
                            
                            if(esg_service->schedule) {
                                EsgScheduleEvent* event = esg_service->schedule;
                                while(event) {
                                    EsgProgramInfo* prog = merged_programs;
                                    while(prog) {
                                        if (strcmp(prog->id, event->programId) == 0) {
                                            schedule_items[schedule_count].event = event;
                                            schedule_items[schedule_count].program = prog;
                                            // Parse timestamp (milliseconds since epoch)
                                            schedule_items[schedule_count].timestamp = atoll(event->startTime) / 1000;
                                            schedule_count++;
                                            break;
                                        }
                                        prog = prog->next;
                                    }
                                    event = event->next;
                                }
                                
                                // Sort by timestamp
                                for (int a = 0; a < schedule_count - 1; a++) {
                                    for (int b = 0; b < schedule_count - a - 1; b++) {
                                        if (schedule_items[b].timestamp > schedule_items[b+1].timestamp) {
                                            ScheduleItem temp = schedule_items[b];
                                            schedule_items[b] = schedule_items[b+1];
                                            schedule_items[b+1] = temp;
                                        }
                                    }
                                }
                                
                                fprintf(f, "<h5>Schedule:</h5><table><tr><th>Time</th><th>Duration</th><th>Program</th></tr>");
                                for (int s = 0; s < schedule_count; s++) {
                                    time_t ts = schedule_items[s].timestamp;
                                    struct tm* tm_info = localtime(&ts);
                                    char time_str[64];
                                    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
                                    
                                    const char* prog_title = schedule_items[s].program ? 
                                        (strlen(schedule_items[s].program->title) > 0 ? schedule_items[s].program->title : schedule_items[s].event->programId) :
                                        schedule_items[s].event->programId;
                                    const char* prog_desc = schedule_items[s].program ? schedule_items[s].program->description : "";
                                    
                                    fprintf(f, "<tr><td>%s</td><td>%s</td><td><strong>%s</strong>", 
                                        time_str, schedule_items[s].event->duration, prog_title);
                                    if (strlen(prog_desc) > 0) {
                                        fprintf(f, "<br><small>%s</small>", prog_desc);
                                    }
                                    fprintf(f, "</td></tr>");
                                }
                                fprintf(f, "</table>");
                            }
                            
                            free(schedule_items);
                            
                            // Show all programs for this service
                            if (strlen(service_num) > 0) {
                                // Collect programs for this service
                                typedef struct {
                                    EsgProgramInfo* program;
                                    int prog_num;
                                } ProgramItem;
                                
                                ProgramItem* program_items = malloc(sizeof(ProgramItem) * 1000);
                                int prog_item_count = 0;
                                
                                char content_pattern[64];
                                snprintf(content_pattern, sizeof(content_pattern), "Content-%s-", service_num);
                                
                                EsgProgramInfo* program = merged_programs;
                                while(program) {
                                    if (strstr(program->id, content_pattern)) {
                                        program_items[prog_item_count].program = program;
                                        
                                        // Extract program number from ID (e.g., "Content-1-258615" -> 258615)
                                        const char* last_dash = strrchr(program->id, '-');
                                        if (last_dash) {
                                            program_items[prog_item_count].prog_num = atoi(last_dash + 1);
                                        } else {
                                            program_items[prog_item_count].prog_num = 999999;
                                        }
                                        prog_item_count++;
                                    }
                                    program = program->next;
                                }
                                
                                // Sort by program number
                                for (int a = 0; a < prog_item_count - 1; a++) {
                                    for (int b = 0; b < prog_item_count - a - 1; b++) {
                                        if (program_items[b].prog_num > program_items[b+1].prog_num) {
                                            ProgramItem temp = program_items[b];
                                            program_items[b] = program_items[b+1];
                                            program_items[b+1] = temp;
                                        }
                                    }
                                }
                                
                                if (prog_item_count > 0) {
                                    fprintf(f, "<h5>All Programs:</h5>");
                                    fprintf(f, "<table><tr><th>Program</th><th>Description</th></tr>");
                                    
                                    for (int p = 0; p < prog_item_count; p++) {
                                        EsgProgramInfo* prog = program_items[p].program;
                                        fprintf(f, "<tr><td>");
                                        
                                        // Show program icon if available
                                        if (prog->icons) {
                                            fprintf(f, "<img src='%s' alt='%s' style='max-width: 100px; max-height: 100px; float: left; margin-right: 10px;' onerror=\"this.style.display='none';\">",
                                                    prog->icons->uri, prog->title);
                                        }
                                        
                                        fprintf(f, "<strong>%s</strong><br><small>%s</small></td><td>%s</td></tr>", 
                                                strlen(prog->title) > 0 ? prog->title : prog->id,
                                                prog->id,
                                                prog->description);
                                    }
                                    fprintf(f, "</table>");
                                }
                                
                                free(program_items);
                            }
                            
                            // Display raw XML for this service
                            for (int sx_idx = 0; sx_idx < service_xml_count; sx_idx++) {
                                if (strstr(service_xmls[sx_idx].service_id, esg_service->id)) {
                                    fprintf(f, "<details><summary>Raw XML (%d fragments)</summary><pre>", 
                                            service_xmls[sx_idx].xml_count);
                                    for (int x = 0; x < service_xmls[sx_idx].xml_count; x++) {
                                        fprintf(f, "\n\n<!-- Fragment %d -->\n", x + 1);
                                        fprintf_escaped_xml(f, service_xmls[sx_idx].xmls[x]);
                                    }
                                    fprintf(f, "</pre></details>");
                                    break;
                                }
                            }
                            
                            fprintf(f, "</div></details>\n");
                        }
                        
                        free(service_array);
                        
                        // Cleanup
                        for (int sx_idx = 0; sx_idx < service_xml_count; sx_idx++) {
                            free(service_xmls[sx_idx].xmls);
                        }
                        free(service_xmls);
                        
                        fprintf(f, "</div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_USER_SERVICE_DESCRIPTION: {
                        usd_route_count++;
                        UserServiceDescriptionData* usd_data = (UserServiceDescriptionData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>User Service Description (ROUTE) Instance %d</summary>\n", usd_route_count);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Type</th><th>Version</th><th>User Agent</th><th>Filter Codes</th></tr></thead>\n<tbody>\n");
                        UsdEntry* entry = usd_data->head;
                        while(entry) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n", entry->contentType, entry->version, entry->userAgent, entry->filterCodes);
                            entry = entry->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_USBD: {
                        usd_mmt_count++;
                        UsdbData* usbd_data = (UsdbData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>User Service Bundle Description (USBD) Instance %d</summary>\n", usd_mmt_count);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>ID</th><th>Content Type</th><th>Version</th></tr></thead>\n<tbody>\n");
                        UsdEntryMmt* entry = usbd_data->head;
                        while(entry) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", entry->id, entry->contentType, entry->version);
                            entry = entry->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_USD: {
                        UsdData* usd_data = (UsdData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>User Service Description (USD) - %s</summary>\n", usd_data->serviceName);
                        fprintf(f, "<div class='details-content'>\n");
                        fprintf(f, "<table><tr><th>Field</th><th>Value</th></tr>");
                        fprintf(f, "<tr><td><strong>Service ID</strong></td><td>%s</td></tr>", usd_data->serviceId);
                        if(strlen(usd_data->mmtPackageId) > 0)
                            fprintf(f, "<tr><td><strong>MMT Package ID</strong></td><td>%s</td></tr>", usd_data->mmtPackageId);
                        fprintf(f, "</table>");
                        
                        if(usd_data->components) {
                            fprintf(f, "<h4>Components:</h4><table><tr><th>Component ID</th><th>Type</th><th>Role</th><th>Description</th></tr>");
                            UsdComponent* comp = usd_data->components;
                            while(comp) {
                                fprintf(f, "<tr><td>%s</td><td>%d</td><td>%d</td><td>%s</td></tr>", 
                                    comp->componentId, comp->componentType, comp->componentRole, comp->description);
                                comp = comp->next;
                            }
                            fprintf(f, "</table>");
                        }
                        
                        fprintf(f, "<h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_DWD: {
                        dwd_count++;
                        fprintf(f, "<details><summary>Dynamic Window Description (DWD) Instance %d</summary>\n", dwd_count);
                        fprintf(f, "<div class='details-content'><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_SERVICE_SIGNALING: {
                        service_signaling_count++;
                        ServiceSignalingData* meta_data = (ServiceSignalingData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>Service Signaling (Metadata Envelope) %d</summary>\n", service_signaling_count);
                        fprintf(f, "<div class='details-content'><table>\n<thead><tr><th>Content Type</th><th>Version</th></tr></thead>\n<tbody>\n");
                        ServiceSignalingFragment* frag = meta_data->head;
                        while(frag) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td></tr>\n", frag->contentType, frag->version);
                            frag = frag->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_STSID: {
                        stsid_count++;
                        StsidData* stsid_data = (StsidData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>S-TSID (Stream Description) Instance %d</summary>\n", stsid_count);
                        fprintf(f, "<div class='details-content'><h4>ROUTE Stream: %s:%s</h4><table>\n<thead><tr><th>TSI</th><th>Representation ID</th><th>Content Type</th><th>Content Ratings</th></tr></thead>\n<tbody>\n", stsid_data->dIpAddr, stsid_data->dPort);
                        StsidLogicalStream* ls = stsid_data->head_ls;
                        while(ls) {
                             fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td><td>", ls->tsi, ls->repId, ls->contentType);
                             ContentRatingInfo* rating = ls->head_rating;
                             if (!rating) {
                                 fprintf(f, "N/A");
                             } else {
                                 while(rating) {
                                     fprintf_escaped_xml(f, rating->value);
                                     fprintf(f, "<br>");
                                     rating = rating->next;
                                 }
                             }
                             fprintf(f, "</td></tr>\n");
                            ls = ls->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_MP_TABLE_XML: {
                        mp_table_xml_count++;
                        MpTableData* mpt_data = (MpTableData*)g_lls_tables[j].parsed_data;
                        fprintf(f, "<details><summary>MMT Signaling (MP Table - XML) Instance %d</summary>\n", mp_table_xml_count);
                        fprintf(f, "<div class='details-content'><h4>MMT Package ID: %s</h4><table>\n<thead><tr><th>Asset ID</th><th>Asset Type</th><th>Packet ID</th></tr></thead>\n<tbody>\n", mpt_data->mptPackageId);
                        MptAsset* asset = mpt_data->head_asset;
                        while(asset) {
                            fprintf(f, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n", asset->assetId, asset->assetType, asset->packetId);
                            asset = asset->next;
                        }
                        fprintf(f, "</tbody></table><h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[j].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_MP_TABLE_BINARY: {
                        mp_table_binary_count++;
                        ProprietaryMptData* mpt_data = (ProprietaryMptData*)g_lls_tables[j].parsed_data;
                        
                        if (!mpt_data || !mpt_data->assets) {
                            fprintf(f, "<details><summary>MMT Package Table Instance %d - No Data</summary></details>\n", 
                                    mp_table_binary_count);
                            break;
                        }
                        
                        fprintf(f, "<details><summary>MMT Package Table (MPT) Instance %d - Package: %s</summary>\n", 
                                mp_table_binary_count, 
                                mpt_data->package_descriptor[0] ? mpt_data->package_descriptor : "Unknown");
                        fprintf(f, "<div class='details-content'>\n");
                        
                        // MPT Header
                        fprintf(f, "<h4>MPT Information</h4>\n");
                        fprintf(f, "<table><tr><th>Field</th><th>Value</th></tr>\n");
                        fprintf(f, "<tr><td><strong>Table ID</strong></td><td>0x%02X</td></tr>\n", mpt_data->table_id);
                        fprintf(f, "<tr><td><strong>Version</strong></td><td>%d</td></tr>\n", mpt_data->version);
                        fprintf(f, "<tr><td><strong>Package Descriptor</strong></td><td>%s</td></tr>\n", 
                                mpt_data->package_descriptor);
                        fprintf(f, "<tr><td><strong>Number of Assets</strong></td><td>%d</td></tr>\n", mpt_data->num_assets);
                        fprintf(f, "</table>\n");
                        
                        // Assets
                        fprintf(f, "<h4>Assets</h4>\n");
                        fprintf(f, "<table>\n<thead><tr><th>Packet ID</th><th>Asset Type</th><th>Codec</th><th>Asset ID</th></tr></thead>\n<tbody>\n");
                        
                        ProprietaryMptAsset* asset = mpt_data->assets;
                        while(asset) {
                            fprintf(f, "<tr><td><strong>%u</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>\n", 
                                    asset->packet_id, asset->asset_type, asset->codec, asset->asset_id);
                            asset = asset->next;
                        }
                        
                        fprintf(f, "</tbody></table></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_MP_TABLE_PATTERN_MATCHED: {
                        mp_table_binary_count++;
                        BinaryMptData* bin_mpt_data = (BinaryMptData*)g_lls_tables[j].parsed_data;
                        
                        if (!bin_mpt_data || !bin_mpt_data->head_asset) {
                            fprintf(f, "<details><summary>MMT Package Table Instance %d (Pattern Matched) - No Data</summary></details>\n", 
                                    mp_table_binary_count);
                            break;
                        }
                        
                        fprintf(f, "<details><summary>MMT Package Table (MPT) Instance %d (Pattern Matched)</summary>\n", mp_table_binary_count);
                        fprintf(f, "<div class='details-content'>\n");
                        fprintf(f, "<p><em>Note: This MPT was parsed using pattern matching due to non-standard format.</em></p>\n");
                        fprintf(f, "<h4>Assets</h4>\n");
                        fprintf(f, "<table>\n<thead><tr><th>Packet ID</th><th>Asset Type</th><th>Codec</th><th>Asset ID</th></tr></thead>\n<tbody>\n");
                        
                        BinaryMptAsset* asset = bin_mpt_data->head_asset;
                        while(asset) {
                            fprintf(f, "<tr><td><strong>%u</strong></td><td>%s</td><td>%s</td><td>%s</td></tr>\n", 
                                    asset->packetId, asset->assetType, asset->codec, asset->assetId);
                            asset = asset->next;
                        }
                        
                        fprintf(f, "</tbody></table></div></details>\n");
                        break;
                    }
                    
                    default: break;
                }
            }
        }
        
        // Look for associated Broadspan (DDA-AS) data from UDSTs
        int udst_instance_count = 0;
        for (int k = 0; k < g_lls_table_count; k++) {
            if (g_lls_tables[k].type == TABLE_TYPE_UDST) {
                UdstData* udst_data = (UdstData*)g_lls_tables[k].parsed_data;
                BroadSpanServiceInfo* bss_info = udst_data->head_service;
                while (bss_info) {
                    RsrvInfo* rsrv = bss_info->head_rsrv;
                    if (rsrv && strcmp(rsrv->srvid, service->serviceId) == 0) {
                        udst_linked_flags[k] = 1; // Mark this UDST as linked
                        found_items_for_service = 1;
                        udst_instance_count++;
                        fprintf(f, "<details><summary>Data Distribution &amp; Ancillary Services (UDST) Instance %d</summary>", udst_instance_count);
                        fprintf(f, "<div class='details-content'>\n");
                        fprintf(f, "<h3>BroadSpan Service: %s</h3>\n", bss_info->name);
                        fprintf(f, "<ul>\n");
                        fprintf(f, "<li><strong>Reservation Name:</strong> %s</li>\n", rsrv->name);
                        fprintf(f, "<li><strong>Service ID in UDST:</strong> %s</li>\n", rsrv->srvid);
                        fprintf(f, "<li><strong>Destination:</strong> %s:%s</li>\n", rsrv->destIP, rsrv->destPort);
                        fprintf(f, "<li><strong>Order ID:</strong> %s</li>\n", rsrv->orderId);
                        fprintf(f, "</ul>\n");
                        fprintf(f, "<h4>Raw XML</h4><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[k].content_id);
                        fprintf(f, "</pre></div></details>\n");
                    }
                    bss_info = bss_info->next;
                }
            }
        }

        if (!found_items_for_service) {
            fprintf(f, "<p class='not-found'>No associated ROUTE/DASH or MMT signaling tables found for this service.</p>\n");
        }

        fprintf(f, "</div>\n");
    }

    // --- Global LLS Tables Section ---
    int header_printed = 0; // Flag to ensure the header is printed only once.

    // A single loop to find and print tables.
    for (int i = 0; i < g_lls_table_count; i++) {
        // This is the outer condition, same as before.
        if (g_lls_tables[i].destinationIp[0] == '\0' && 
            g_lls_tables[i].type != TABLE_TYPE_SLT && 
            g_lls_tables[i].type != TABLE_TYPE_CDT) {
            
            // This variable determines if we will actually print for the current table.
            int should_print_this_table = 0; 
            
            // Check the specific conditions from your switch statement.
            switch(g_lls_tables[i].type) {
                case TABLE_TYPE_UCT:
                    // UCT tables are always printed if they match the outer condition.
                    should_print_this_table = 1;
                    break;
                case TABLE_TYPE_UDST:
                    // UDST tables are only printed if they are not linked.
                    if (udst_linked_flags[i] == 0) {
                        should_print_this_table = 1;
                    }
                    break;
                case TABLE_TYPE_SYSTEM_TIME:
                    should_print_this_table = 1;
                    break;
                default:
                    break;
            }

            // If this is the first table we're going to print, print the header first.
            if (should_print_this_table && !header_printed) {
                fprintf(f, "<h2>Other Global LLS Tables</h2>\n");
                header_printed = 1; // Set the flag so we don't print the header again.
            }

            // Now, if we should print, execute the original printing logic.
            if (should_print_this_table) {
                switch(g_lls_tables[i].type) {
                    case TABLE_TYPE_UCT: {
                        UctData* uct_data = (UctData*)g_lls_tables[i].parsed_data;
                        fprintf(f, "<details><summary>User Content Table (UCT / NDP)</summary><div class='details-content'>\n");
                        NdPackage* package = uct_data->head_package;
                        while(package) {
                            fprintf(f, "<h3>Package: %s (IP: %s:%s)</h3>\n", package->name, package->dstIP, package->dstPort);
                            fprintf(f, "<table>\n<thead><tr><th>Element Name</th><th>TSI</th></tr></thead>\n<tbody>\n");
                            NdElement* element = package->head_element;
                            while (element) { fprintf(f, "<tr><td>%s</td><td>%s</td></tr>\n", element->name, element->tsi); element = element->next; }
                            fprintf(f, "</tbody></table>\n");
                            package = package->next;
                        }
                        fprintf(f, "<details><summary>Raw XML</summary><pre>");
                        fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                        fprintf(f, "</pre></div></details>\n");
                        break;
                    }
                    case TABLE_TYPE_UDST: {
                        // This check is technically redundant now, but it's safe to keep.
                        if (udst_linked_flags[i] == 0) { 
                            UdstData* udst_data = (UdstData*)g_lls_tables[i].parsed_data;
                            fprintf(f, "<details><summary>Unlinked User Defined Service Table (UDST)</summary><div class='details-content'>\n");
                            BroadSpanServiceInfo* bss_info = udst_data->head_service;
                            while(bss_info) {
                                RsrvInfo* rsrv = bss_info->head_rsrv;
                                fprintf(f, "<h3>BroadSpan Service: %s</h3>\n", bss_info->name);
                                if (rsrv) {
                                    fprintf(f, "<ul>\n");
                                    fprintf(f, "<li><strong>Reservation Name:</strong> %s</li>\n", rsrv->name);
                                    fprintf(f, "<li><strong>Service ID in UDST:</strong> %s</li>\n", rsrv->srvid);
                                    fprintf(f, "<li><strong>Destination:</strong> %s:%s</li>\n", rsrv->destIP, rsrv->destPort);
                                    fprintf(f, "<li><strong>Order ID:</strong> %s</li>\n", rsrv->orderId);
                                    fprintf(f, "</ul>\n");
                                }
                                bss_info = bss_info->next;
                            }
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></div></details>\n");
                        }
                        break;
                    }
                    case TABLE_TYPE_SYSTEM_TIME:
                    // System Time
                    int found_system_time = 0;
                    for (int i = 0; i < g_lls_table_count; i++) {
                        if (g_lls_tables[i].type == TABLE_TYPE_SYSTEM_TIME) {
                            found_system_time = 1;
                            SystemTimeData* time_data = (SystemTimeData*)g_lls_tables[i].parsed_data;
                            fprintf(f, "<details><summary>System Time Details - Actual Timestamp in L1Detail</summary><div class='details-content'>\n");
                            fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
                            if (time_data->currentUtcOffset[0] != '\0') { fprintf(f, "<tr><td>currentUtcOffset</td><td>%s</td></tr>\n", time_data->currentUtcOffset); }
                            if (time_data->ptpPrepend[0] != '\0') { fprintf(f, "<tr><td>ptpPrepend</td><td>%s</td></tr>\n", time_data->ptpPrepend); }
                            if (time_data->leap59[0] != '\0') { fprintf(f, "<tr><td>leap59</td><td>%s</td></tr>\n", time_data->leap59); }
                            if (time_data->leap61[0] != '\0') { fprintf(f, "<tr><td>leap61</td><td>%s</td></tr>\n", time_data->leap61); }
                            if (time_data->utcLocalOffset[0] != '\0') { fprintf(f, "<tr><td>utcLocalOffset</td><td>%s</td></tr>\n", time_data->utcLocalOffset); }
                            if (time_data->dsStatus[0] != '\0') { fprintf(f, "<tr><td>dsStatus</td><td>%s</td></tr>\n", time_data->dsStatus); }
                            if (time_data->dsDayOfMonth[0] != '\0') { fprintf(f, "<tr><td>dsDayOfMonth</td><td>%s</td></tr>\n", time_data->dsDayOfMonth); }
                            if (time_data->dsHour[0] != '\0') { fprintf(f, "<tr><td>dsHour</td><td>%s</td></tr>\n", time_data->dsHour); }
                            fprintf(f, "</tbody></table>\n");
                            fprintf(f, "<details><summary>Raw XML</summary><pre>");
                            fprintf_escaped_xml(f, g_lls_tables[i].content_id);
                            fprintf(f, "</pre></details></div></details>\n");
                            break; // Only show first System Time
                        }
                    }
                    if (!found_system_time) {
                        fprintf(f, "<details><summary>System Time Details - Not Found</summary>\n");
                        fprintf(f, "<div class='details-content'><p class='not-found'>No System Time tables found in this capture.</p></div></details>\n");
                    }
                    default: break;
                }
            }
        }
        
    }
    
    // --- Input Info Section ---
    fprintf(f, "<h2>Input Info</h2>\n");
    fprintf(f, "<table>\n<thead><tr><th>Attribute</th><th>Value</th></tr></thead>\n<tbody>\n");
    
    // Input type
    fprintf(f, "<tr><td><strong>Input Type</strong></td><td>%s</td></tr>\n", get_input_type_string(g_input_type));
    
    // File name
    fprintf(f, "<tr><td><strong>File Name</strong></td><td>%s</td></tr>\n", g_input_filename);
    
    // Total packets processed
    fprintf(f, "<tr><td><strong>Total Packets Processed</strong></td><td>%d</td></tr>\n", g_packet_count);
    
    // PCAP duration (only for PCAP files)
    if (g_input_type == INPUT_TYPE_PCAP && g_pcap_timing_valid && g_packet_count > 1) {
        double duration_seconds = (double)(g_last_packet_time.tv_sec - g_first_packet_time.tv_sec) + 
                                 (double)(g_last_packet_time.tv_usec - g_first_packet_time.tv_usec) / 1000000.0;
        
        if (duration_seconds >= 60.0) {
            int minutes = (int)(duration_seconds / 60);
            double remaining_seconds = duration_seconds - (minutes * 60);
            fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>%d minutes, %.1f seconds</td></tr>\n", 
                    minutes, remaining_seconds);
        } else {
            fprintf(f, "<tr><td><strong>Capture Duration</strong></td><td>%.1f seconds</td></tr>\n", duration_seconds);
        }
    }
    
    // File modification time
    struct stat file_stat;
    if (stat(g_input_filename, &file_stat) == 0) {
        char mod_time_str[64];
        struct tm *mod_tm = localtime(&file_stat.st_mtime);
        strftime(mod_time_str, sizeof(mod_time_str), "%Y-%m-%d %H:%M:%S %Z", mod_tm);
        fprintf(f, "<tr><td><strong>File Last Modified</strong></td><td>%s</td></tr>\n", mod_time_str);
    } else {
        fprintf(f, "<tr><td><strong>File Last Modified</strong></td><td>Unable to determine</td></tr>\n");
    }
    
    // Current time (when analysis was run)
    time_t current_time = time(NULL);
    char current_time_str[64];
    struct tm *current_tm = localtime(&current_time);
    strftime(current_time_str, sizeof(current_time_str), "%Y-%m-%d %H:%M:%S %Z", current_tm);
    fprintf(f, "<tr><td><strong>Analysis Run Time</strong></td><td>%s</td></tr>\n", current_time_str);
    
    fprintf(f, "</tbody></table>\n");
    
    consolidate_data_usage_entries();
    generate_data_usage_chart(f);

    fprintf(f, "</div>\n</body>\n</html>\n");

    // After the loop, if the header was never printed, it means nothing was found.
    if (!header_printed) {
        //fprintf(f, "<p class='not-found'>No other global LLS tables found.</p>\n");
    }

    fclose(f);
    printf("Generated HTML report: %s\n", filename);
}

/**
 * @brief Frees all globally allocated memory.
 */
void cleanup() {
    for (int i = 0; i < g_lls_table_count; i++) {
        free(g_lls_tables[i].content_id);
        free_parsed_data(&g_lls_tables[i]);
    }
    free_reassembly_buffers();
    free_bps_data(g_bps_data);
    g_bps_data = NULL;
    
    if (get_enhanced_l1_signaling_data()) {
        free_enhanced_l1_signaling_data(get_enhanced_l1_signaling_data());
        set_enhanced_l1_signaling_data(NULL);
    }
}

/**
 * @brief Frees any remaining fragment reassembly buffers.
 */
void free_reassembly_buffers() {
    ReassemblyBuffer* current = g_reassembly_head;
    while(current != NULL) {
        ReassemblyBuffer* next = current->next;
        free(current->buffer);
        free(current);
        current = next;
    }
    g_reassembly_head = NULL;
}



void free_usbd_data(UsdbData* data) {
    if (!data) return;
    UsdEntryMmt* current = data->head;
    while (current != NULL) {
        UsdEntryMmt* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

void free_usd_data(UsdData* data) {
    if (!data) return;
    
    // Free components
    UsdComponent* current_comp = data->components;
    while (current_comp != NULL) {
        UsdComponent* next_comp = current_comp->next;
        free(current_comp);
        current_comp = next_comp;
    }
    
    // Free assets (existing code)
    UsdAsset* current = data->assets;
    while (current != NULL) {
        UsdAsset* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory associated with a parsed table struct.
 */
void free_parsed_data(LlsTable* table) {
    if (!table->parsed_data) return;

    switch (table->type) {
        case TABLE_TYPE_SLT:
            free_slt_data((SltData*)table->parsed_data);
            break;
        case TABLE_TYPE_UCT:
            free_uct_data((UctData*)table->parsed_data);
            break;
        case TABLE_TYPE_UDST:
            free_udst_data((UdstData*)table->parsed_data);
            break;
        case TABLE_TYPE_FDT:
            free_fdt_data((FDTInstanceData*)table->parsed_data);
            break;
        case TABLE_TYPE_MPD:
            free_mpd_data((MpdData*)table->parsed_data);
            break;
        case TABLE_TYPE_HELD:
            free_held_data((HeldData*)table->parsed_data);
            break;
        case TABLE_TYPE_ESG_FRAGMENT:
            free_esg_data((EsgFragmentData*)table->parsed_data);
            break;
        case TABLE_TYPE_SGDD: {
            SgddData* sgdd = (SgddData*)table->parsed_data;
            if (sgdd) {
                SgddEntry* entry = sgdd->entries;
                while (entry) {
                    SgddEntry* next_entry = entry->next;
                    SgddDeliveryUnit* unit = entry->deliveryUnits;
                    while (unit) {
                        SgddDeliveryUnit* next_unit = unit->next;
                        SgddFragment* frag = unit->fragments;
                        while (frag) {
                            SgddFragment* next_frag = frag->next;
                            free(frag);
                            frag = next_frag;
                        }
                        free(unit);
                        unit = next_unit;
                    }
                    free(entry);
                    entry = next_entry;
                }
                free(sgdd);
            }
            break;
        }
        case TABLE_TYPE_USER_SERVICE_DESCRIPTION:
            free_user_service_description_data((UserServiceDescriptionData*)table->parsed_data);
            break;
        case TABLE_TYPE_USBD:
            free_usbd_data((UsdbData*)table->parsed_data);
            break;
        case TABLE_TYPE_USD:
            free_usd_data((UsdData*)table->parsed_data);
            break;
        case TABLE_TYPE_SERVICE_SIGNALING:
            free_service_signaling_data((ServiceSignalingData*)table->parsed_data);
            break;
        case TABLE_TYPE_STSID:
            free_stsid_data((StsidData*)table->parsed_data);
            break;
        case TABLE_TYPE_MP_TABLE_XML:
            free_mp_table_data((MpTableData*)table->parsed_data);
            break;
        case TABLE_TYPE_MP_TABLE_BINARY:
            // This is now ONLY ProprietaryMptData
            free_proprietary_mpt_data((ProprietaryMptData*)table->parsed_data);
            break;

        case TABLE_TYPE_MP_TABLE_PATTERN_MATCHED:
            // This is the old BinaryMptData
            free_binary_mp_table_data((BinaryMptData*)table->parsed_data);
            break;
        case TABLE_TYPE_CDT: {
            CdtData* cdt_data = (CdtData*)table->parsed_data;
            if (cdt_data) {
                free_certificate_info(cdt_data->certificates);
                free(cdt_data);
            }
            break;
        }
        case TABLE_TYPE_SYSTEM_TIME:
        case TABLE_TYPE_SIGNATURE:
        case TABLE_TYPE_DWD: // Placeholder, just free the main struct
            free(table->parsed_data);
            break;
        case TABLE_TYPE_LMT: {
            LmtData* lmt_data = (LmtData*)table->parsed_data;
            if (lmt_data) {
                LmtService* current_service = lmt_data->services;
                while (current_service) {
                    LmtService* next_service = current_service->next;
                    
                    // Free multicast list for this service
                    LmtMulticast* current_multicast = current_service->multicasts;
                    while (current_multicast) {
                        LmtMulticast* next_multicast = current_multicast->next;
                        free(current_multicast);
                        current_multicast = next_multicast;
                    }
                    
                    free(current_service);
                    current_service = next_service;
                }
                free(lmt_data);
            }
            break;
        }
        default:
            free(table->parsed_data); // Default case
            break;
    }
    table->parsed_data = NULL;
}

/**
 * @brief Frees memory for an SltData struct and its linked list of services.
 */
void free_slt_data(SltData* data) {
    if (!data) return;
    ServiceInfo* current = data->head;
    while (current != NULL) {
        ServiceInfo* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a FDTInstanceData struct and its file list.
 */
void free_fdt_data(FDTInstanceData* data) {
    if (!data) return;
    FDTFileInfo* current = data->head;
    while(current != NULL) {
        FDTFileInfo* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a MpdData struct and its contents.
 */
void free_mpd_data(MpdData* data) {
    if (!data) return;
    MpdAdaptationSet* current_as = data->head_as;
    while (current_as != NULL) {
        // Since timelines can be shared across Representations, we must free it carefully.
        SegmentTimelineS* timeline_to_free = NULL;
        if (current_as->head_rep) {
            timeline_to_free = current_as->head_rep->segmentTemplate.timeline;
        }

        MpdRepresentation* current_rep = current_as->head_rep;
        while(current_rep != NULL) {
            MpdRepresentation* next_rep = current_rep->next;
            
            // Free DRM info
            DrmInfo* current_drm = current_rep->drmInfo;
            while (current_drm != NULL) {
                DrmInfo* next_drm = current_drm->next;
                DrmKeyId* current_key = current_drm->keyIds;
                while (current_key != NULL) {
                    DrmKeyId* next_key = current_key->next;
                    free(current_key);
                    current_key = next_key;
                }
                free(current_drm);
                current_drm = next_drm;
            }
            
            free(current_rep);
            current_rep = next_rep;
        }

        // Now, free the single, shared timeline for the whole Adaptation Set.
        SegmentTimelineS* current_s = timeline_to_free;
        while(current_s != NULL) {
            SegmentTimelineS* next_s = current_s->next;
            free(current_s);
            current_s = next_s;
        }
        
        MpdAdaptationSet* next_as = current_as->next;
        free(current_as);
        current_as = next_as;
    }
    free(data);
}

/**
 * @brief Frees memory for a HeldData struct.
 */
void free_held_data(HeldData* data) {
    if (!data) return;
    free(data);
}

/**
 * @brief Frees memory for a UserServiceDescriptionData struct.
 */
void free_user_service_description_data(UserServiceDescriptionData* data) {
    if (!data) return;
    UsdEntry* current = data->head;
    while (current != NULL) {
        UsdEntry* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a ServiceSignalingData struct.
 */
void free_service_signaling_data(ServiceSignalingData* data) {
    if (!data) return;
    ServiceSignalingFragment* current = data->head;
    while (current != NULL) {
        ServiceSignalingFragment* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for an StsidData struct.
 */
void free_stsid_data(StsidData* data) {
    if (!data) return;
    StsidLogicalStream* current_ls = data->head_ls;
    while (current_ls != NULL) {
        ContentRatingInfo* current_rating = current_ls->head_rating;
        while (current_rating != NULL) {
            ContentRatingInfo* next_rating = current_rating->next;
            free(current_rating);
            current_rating = next_rating;
        }
        StsidLogicalStream* next_ls = current_ls->next;
        free(current_ls);
        current_ls = next_ls;
    }
    free(data);
}

/**
 * @brief Frees memory for an MpTableData struct.
 */
void free_mp_table_data(MpTableData* data) {
    if (!data) return;
    MptAsset* current = data->head_asset;
    while (current != NULL) {
        MptAsset* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a BinaryMptData struct and its linked list of assets.
 */
void free_binary_mp_table_data(BinaryMptData* data) {
    if (!data) return;
    BinaryMptAsset* current = data->head_asset;
    while (current != NULL) {
        BinaryMptAsset* next = current->next;
        free(current);
        current = next;
    }
    free(data);
}

/**
 * @brief Frees memory for a UctData struct and its contents.
 */
void free_uct_data(UctData* data) {
    if (!data) return;
    NdPackage* current_pkg = data->head_package;
    while (current_pkg != NULL) {
        NdElement* current_elem = current_pkg->head_element;
        while(current_elem != NULL) {
            NdElement* next_elem = current_elem->next;
            free(current_elem);
            current_elem = next_elem;
        }
        NdPackage* next_pkg = current_pkg->next;
        free(current_pkg);
        current_pkg = next_pkg;
    }
    free(data);
}

/**
 * @brief Frees memory for a UdstData struct and its contents.
 */
void free_udst_data(UdstData* data) {
    if (!data) return;
    BroadSpanServiceInfo* current_svc = data->head_service;
    while (current_svc != NULL) {
        if (current_svc->head_rsrv) {
            free(current_svc->head_rsrv);
        }
        BroadSpanServiceInfo* next_svc = current_svc->next;
        free(current_svc);
        current_svc = next_svc;
    }
    free(data);
}

