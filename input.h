#ifndef INPUT_H
#define INPUT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

// Fallback definition if u_char is still not defined
#ifndef u_char
typedef unsigned char u_char;
#endif

// Input type constants
#define INPUT_TYPE_PCAP 0
#define INPUT_TYPE_DEBUG 1
#define INPUT_TYPE_ALP_PCAP 2
#define INPUT_TYPE_STLTP 3

// ALP parsing return codes
#define ALP_PARSE_ERROR -1
#define ALP_PARSE_IPV4 0
#define ALP_PARSE_SIGNALING 1
#define ALP_PARSE_EXTENSION_ONLY 2

// ALP packet types
#define ALP_PACKET_TYPE_IPV4 0x00
#define ALP_PACKET_TYPE_COMPRESSED_IPV4 0x01
#define ALP_PACKET_TYPE_LINK_LAYER_SIGNALING 0x04
#define ALP_PACKET_TYPE_PACKET_TYPE_EXTENSION 0x07

#ifndef DLT_ATSC_ALP
#define DLT_ATSC_ALP 289
#endif

// ============================================================================
// STLTP Constants per A/324
// ============================================================================

// Outer tunnel RTP payload type (Table 6.2)
#define STLTP_OUTER_PT 97   // 0x61 - STL Transport Protocol

// Inner stream RTP payload types (Section 9)
#define STLTP_PT_TM       76   // 0x4C - Timing & Management
#define STLTP_PT_PREAMBLE 77   // 0x4D - Preamble (L1-Basic + L1-Detail)
#define STLTP_PT_BBP      78   // 0x4E - Baseband Packets

// Inner stream destination ports (Section 9)
#define STLTP_PORT_BBP_BASE  30000  // Baseband Packets start (PLP 0)
#define STLTP_PORT_BBP_MAX   30063  // Baseband Packets end (PLP 63)
#define STLTP_PORT_PREAMBLE  30064  // Preamble stream
#define STLTP_PORT_TM        30065  // Timing & Management
#define STLTP_PORT_SECURITY  30066  // Security Data Stream

// Inner stream multicast address
#define STLTP_INNER_MCAST_ADDR 0xEF003330  // 239.0.51.48

// L1 signaling sizes (A/322)
#define STLTP_L1_BASIC_SIZE 25  // 200 bits = 25 bytes

// ALP header structure
typedef struct {
    uint8_t packet_type;
    uint8_t payload_configuration;
    uint16_t length;
    uint8_t* payload;
} alp_packet_t;

// STLTP extraction results
typedef struct {
    uint8_t *alp_data;           // Extracted ALP packets (descrambled)
    size_t alp_size;
    uint8_t *l1_basic;           // L1-Basic data (raw bytes, 25 bytes)
    size_t l1_basic_size;
    uint8_t *l1_detail;          // L1-Detail data (raw bytes, variable)
    size_t l1_detail_size;
    char *l1_basic_b64;          // L1-Basic as base64 string
    char *l1_detail_b64;         // L1-Detail as base64 string
    uint8_t *timing_mgmt;        // Timing & Management data
    size_t timing_mgmt_size;
    // Stats
    uint32_t alp_packet_count;
    uint32_t preamble_packet_count;
    uint32_t timing_packet_count;
    uint32_t rtp_packet_count;
} stltp_extract_t;

// Function prototypes - existing
int detect_file_type(const char* filename);
const char* get_input_type_string(int input_type);
uint8_t* remove_variable_artifacts(const uint8_t *data, size_t data_len, size_t *cleaned_len);
void multicast_ip_to_mac(uint32_t ip, uint8_t *mac);
int create_virtual_pcap_from_debug(const char *debug_filename, uint8_t **pcap_data, size_t *pcap_size);
int parse_alp_packet(const u_char* alp_data, int alp_len, const u_char** ip_payload, int* ip_len, 
                     const u_char** signaling_payload, int* signaling_len);

// Function prototypes - STLTP support
int detect_stltp_file(const char *filename);
stltp_extract_t* stltp_extract_create(void);
void stltp_extract_free(stltp_extract_t *extract);
int process_stltp_file(const char *filename, stltp_extract_t *extract);
int create_virtual_alp_pcap_from_stltp(const char *stltp_filename, uint8_t **pcap_data, size_t *pcap_size,
                                       char **l1_basic_b64, char **l1_detail_b64);

// Base64 encoding helper
char* base64_encode(const uint8_t *data, size_t input_length, size_t *output_length);

#endif // INPUT_H
