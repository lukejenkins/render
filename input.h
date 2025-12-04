#ifndef INPUT_H
#define INPUT_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>  // ADD THIS - provides u_char on most systems

// Fallback definition if u_char is still not defined
#ifndef u_char
typedef unsigned char u_char;
#endif

// Input type constants
#define INPUT_TYPE_PCAP 0
#define INPUT_TYPE_DEBUG 1
#define INPUT_TYPE_ALP_PCAP 2

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

// ALP header structure
typedef struct {
    uint8_t packet_type;
    uint8_t payload_configuration;
    uint16_t length;
    uint8_t* payload;
} alp_packet_t;

// Function prototypes
int detect_file_type(const char* filename);
const char* get_input_type_string(int input_type);
uint8_t* remove_variable_artifacts(const uint8_t *data, size_t data_len, size_t *cleaned_len);
void multicast_ip_to_mac(uint32_t ip, uint8_t *mac);
int create_virtual_pcap_from_debug(const char *debug_filename, uint8_t **pcap_data, size_t *pcap_size);
int parse_alp_packet(const u_char* alp_data, int alp_len, const u_char** ip_payload, int* ip_len, 
                     const u_char** signaling_payload, int* signaling_len);

#endif // INPUT_H
