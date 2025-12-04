#include "input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <time.h>
#include <strings.h>

const char* get_input_type_string(int input_type) {
    switch(input_type) {
        case INPUT_TYPE_PCAP: return "PCAP File";
        case INPUT_TYPE_DEBUG: return "Debug File";
        case INPUT_TYPE_ALP_PCAP: return "ALP-PCAP File";
        default: return "Unknown";
    }
}

int detect_file_type(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (ext) {
        if (strcasecmp(ext, ".dbg") == 0) {
            return INPUT_TYPE_DEBUG;
        } else if (strcasecmp(ext, ".pcap") == 0 || strcasecmp(ext, ".pcapng") == 0) {
            // First try to detect by examining the file content
            FILE* f = fopen(filename, "rb");
            if (f) {
                // Skip PCAP global header (24 bytes)
                fseek(f, 24, SEEK_SET);
                
                // Read first record header to check link type
                uint32_t record_header[4];
                if (fread(record_header, sizeof(uint32_t), 4, f) == 4) {
                    // Skip packet data, read actual PCAP file header link type
                    fseek(f, 20, SEEK_SET); // Link type is at offset 20 in global header
                    uint32_t link_type;
                    if (fread(&link_type, sizeof(uint32_t), 1, f) == 1) {
                        if (link_type == DLT_ATSC_ALP || link_type == 289) {
                            fclose(f);
                            return INPUT_TYPE_ALP_PCAP;
                        }
                    }
                }
                fclose(f);
            }
            
            // Fallback to filename-based detection
            if (strstr(filename, "alp") || strstr(filename, "ALP")) {
                return INPUT_TYPE_ALP_PCAP;
            }
            return INPUT_TYPE_PCAP;
        }
    }
    
    // If no clear extension, try to detect by file content
    FILE* f = fopen(filename, "rb");
    if (!f) return INPUT_TYPE_PCAP; // Default assumption
    
    uint32_t magic;
    if (fread(&magic, sizeof(magic), 1, f) == 1) {
        fclose(f);
        // Check for PCAP magic numbers
        if (magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1 || 
            magic == 0x0a0d0d0a) { // pcapng
            // For now, assume regular PCAP unless filename suggests ALP
            if (strstr(filename, "alp") || strstr(filename, "ALP")) {
                return INPUT_TYPE_ALP_PCAP;
            }
            return INPUT_TYPE_PCAP;
        }
    } else {
        fclose(f);
    }
    
    return INPUT_TYPE_DEBUG; // Assume debug if not clearly PCAP
}

uint8_t* remove_variable_artifacts(const uint8_t *data, size_t data_len, size_t *cleaned_len) {
    uint8_t *cleaned_data = malloc(data_len);
    if (!cleaned_data) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }
    
    size_t pos = 0;
    size_t cleaned_pos = 0;
    int removed_count = 0;
    int three_byte_count = 0;
    int four_byte_count = 0;
    
    printf("Removing variable-length artifacts (3 or 4 bytes based on second byte flag)...\n");
    
    while (pos < data_len) {
        if (pos + 188 <= data_len) {
            // Check if this starts with e7 (artifact marker)
            if (data[pos] == 0xe7 && pos + 1 < data_len) {
                // Check the second byte's high nibble to determine artifact length
                uint8_t second_byte = data[pos + 1];
                uint8_t flag_nibble = second_byte >> 4;
                
                int artifact_len;
                if (flag_nibble == 0x0) {
                    // 0X means 3-byte artifact
                    artifact_len = 3;
                    three_byte_count++;
                } else if (flag_nibble == 0x4) {
                    // 4X means 4-byte artifact
                    artifact_len = 4;
                    four_byte_count++;
                } else {
                    // Unknown flag, assume 3-byte for safety
                    artifact_len = 3;
                    three_byte_count++;
                }
                
                // Skip the artifact
                pos += artifact_len;
                removed_count++;
                
                // Copy the remaining data in this 188-byte chunk
                int remaining_in_chunk = 188 - artifact_len;
                if (pos + remaining_in_chunk <= data_len) {
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining_in_chunk);
                    cleaned_pos += remaining_in_chunk;
                    pos += remaining_in_chunk;
                } else {
                    // Not enough data left, copy what remains
                    int remaining = data_len - pos;
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                    cleaned_pos += remaining;
                    break;
                }
            } else {
                // No e7 marker, copy the whole 188-byte chunk
                memcpy(cleaned_data + cleaned_pos, data + pos, 188);
                cleaned_pos += 188;
                pos += 188;
            }
        } else {
            // Less than 188 bytes remaining - handle end of file
            int remaining = data_len - pos;
            if (remaining >= 2 && data[pos] == 0xe7) {
                uint8_t second_byte = data[pos + 1];
                uint8_t flag_nibble = second_byte >> 4;
                int artifact_len = (flag_nibble == 0x4) ? 4 : 3;
                
                if (remaining >= artifact_len) {
                    pos += artifact_len;
                    removed_count++;
                    
                    if (pos < data_len) {
                        int final_remaining = data_len - pos;
                        memcpy(cleaned_data + cleaned_pos, data + pos, final_remaining);
                        cleaned_pos += final_remaining;
                    }
                } else {
                    // Not enough data for full artifact, copy as-is
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                    cleaned_pos += remaining;
                }
            } else {
                // No artifact marker, copy remaining data as-is
                memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                cleaned_pos += remaining;
            }
            break;
        }
    }
    
    printf("Removed %d variable-length artifacts\n", removed_count);
    printf("  3-byte artifacts (0X): %d\n", three_byte_count);
    printf("  4-byte artifacts (4X): %d\n", four_byte_count);
    printf("Total bytes removed: %zu (%.2f%%)\n", 
           data_len - cleaned_pos, (double)(data_len - cleaned_pos) / data_len * 100.0);
    
    *cleaned_len = cleaned_pos;
    return cleaned_data;
}

void multicast_ip_to_mac(uint32_t ip, uint8_t *mac) {
    mac[0] = 0x01;
    mac[1] = 0x00;
    mac[2] = 0x5e;
    mac[3] = (ip >> 16) & 0x7f;
    mac[4] = (ip >> 8) & 0xff;
    mac[5] = ip & 0xff;
}

int create_virtual_pcap_from_debug(const char *debug_filename, uint8_t **pcap_data, size_t *pcap_size) {
    // Read debug file
    FILE *input_file = fopen(debug_filename, "rb");
    if (!input_file) {
        fprintf(stderr, "Error: Cannot open debug file %s\n", debug_filename);
        return 1;
    }
    
    // Get file size
    fseek(input_file, 0, SEEK_END);
    size_t file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    printf("Debug file size: %zu bytes\n", file_size);
    
    // Read entire file into memory
    uint8_t *raw_data = malloc(file_size);
    if (!raw_data) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(input_file);
        return 1;
    }
    
    size_t bytes_read = fread(raw_data, 1, file_size, input_file);
    fclose(input_file);
    
    if (bytes_read != file_size) {
        fprintf(stderr, "Error reading debug file\n");
        free(raw_data);
        return 1;
    }
    
    // Remove artifacts
    size_t cleaned_len;
    uint8_t *cleaned_data = remove_variable_artifacts(raw_data, file_size, &cleaned_len);
    free(raw_data);
    
    if (!cleaned_data) {
        return 1;
    }
    
    printf("Cleaned data size: %zu bytes\n", cleaned_len);
    
    // Find IPv4 multicast UDP packets
    printf("Scanning for IPv4 multicast UDP packets...\n");
    
    size_t *packet_offsets = malloc(cleaned_len / 20 * sizeof(size_t));
    size_t packet_count = 0;
    
    for (size_t pos = 0; pos < cleaned_len - 20; pos++) {
        if (cleaned_data[pos] == 0x45 &&           // IPv4 with standard header
            cleaned_data[pos + 9] == 17 &&         // UDP protocol
            cleaned_data[pos + 16] >= 224 &&       // Multicast IP range
            cleaned_data[pos + 16] <= 239) {
            
            uint8_t version = cleaned_data[pos] >> 4;
            uint8_t ihl = cleaned_data[pos] & 0xF;
            
            if (version == 4 && ihl >= 5) {
                packet_offsets[packet_count++] = pos;
            }
        }
    }
    
    printf("Found %zu potential packets in debug file\n", packet_count);
    
    // Estimate PCAP size (header + packets with ethernet headers)
    size_t estimated_size = 24; // PCAP global header
    for (size_t i = 0; i < packet_count; i++) {
        size_t current_start = packet_offsets[i];
        uint16_t total_len = (cleaned_data[current_start + 2] << 8) | cleaned_data[current_start + 3];
        if (total_len >= 20) {
            estimated_size += 16 + 14 + total_len; // pcap record header + ethernet + IP packet
        }
    }
    
    // Allocate virtual PCAP buffer
    *pcap_data = malloc(estimated_size);
    if (!*pcap_data) {
        free(cleaned_data);
        free(packet_offsets);
        return 1;
    }
    
    size_t pcap_pos = 0;
    
    // Write PCAP global header
    struct {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t  thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    } pcap_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1  // Ethernet
    };
    
    memcpy(*pcap_data + pcap_pos, &pcap_hdr, 24);
    pcap_pos += 24;
    
    uint32_t timestamp = (uint32_t)time(NULL);
    
    // Add packets to virtual PCAP
    for (size_t i = 0; i < packet_count; i++) {
        size_t current_start = packet_offsets[i];
        size_t next_start = (i + 1 < packet_count) ? packet_offsets[i + 1] : cleaned_len;
        size_t packet_chunk_len = next_start - current_start;
        
        if (packet_chunk_len < 20) continue;
        
        // Get IP packet length from header
        uint16_t total_len = (cleaned_data[current_start + 2] << 8) | cleaned_data[current_start + 3];
        
        if (total_len >= 20 && total_len <= packet_chunk_len) {
            // Extract destination IP for MAC address generation
            uint32_t dest_ip = (cleaned_data[current_start + 16] << 24) |
                              (cleaned_data[current_start + 17] << 16) |
                              (cleaned_data[current_start + 18] << 8) |
                              cleaned_data[current_start + 19];
            
            // Create Ethernet header
            uint8_t eth_header[14];
            multicast_ip_to_mac(dest_ip, eth_header);  // Destination MAC
            
            // Source MAC
            eth_header[6] = 0x00;
            eth_header[7] = 0x11;
            eth_header[8] = 0x22;
            eth_header[9] = 0x33;
            eth_header[10] = 0x44;
            eth_header[11] = 0x55;
            
            // EtherType (IPv4)
            eth_header[12] = 0x08;
            eth_header[13] = 0x00;
            
            uint32_t full_packet_len = 14 + total_len;
            
            // Write PCAP record header
            struct {
                uint32_t ts_sec;
                uint32_t ts_usec;
                uint32_t incl_len;
                uint32_t orig_len;
            } rec_hdr = {
                .ts_sec = timestamp + i,
                .ts_usec = 0,
                .incl_len = full_packet_len,
                .orig_len = full_packet_len
            };
            
            memcpy(*pcap_data + pcap_pos, &rec_hdr, 16);
            pcap_pos += 16;
            
            // Write Ethernet header + IP packet
            memcpy(*pcap_data + pcap_pos, eth_header, 14);
            pcap_pos += 14;
            memcpy(*pcap_data + pcap_pos, cleaned_data + current_start, total_len);
            pcap_pos += total_len;
        }
    }
    
    *pcap_size = pcap_pos;
    
    free(cleaned_data);
    free(packet_offsets);
    
    printf("Created virtual PCAP with %zu packets (%zu bytes)\n", packet_count, *pcap_size);
    return 0;
}



/**
 * @brief Parses an ALP packet header and extracts the IP payload
 */
int parse_alp_packet(const u_char* alp_data, int alp_len, const u_char** ip_payload, int* ip_len, 
                     const u_char** signaling_payload, int* signaling_len) {
    if (alp_len < 2) {
        return -1;
    }
    
    uint8_t first_byte = alp_data[0];
    uint8_t packet_type = (first_byte >> 5) & 0x07;
    uint8_t payload_config = (first_byte >> 4) & 0x01;
    
    // Initialize output parameters
    *ip_payload = NULL;
    *ip_len = 0;
    *signaling_payload = NULL;
    *signaling_len = 0;
    
    if (packet_type == 0) {
        // IPv4 packet
        int header_offset = 1;  // After first byte
        
        // For ALP IPv4 packets, check the actual length field position
        // payload_config bits indicate the structure
        // If bit 3 (0x08) is set, length is 2 bytes
        // Otherwise length is 1 byte
        if (payload_config & 0x08) {
            header_offset += 2;  // 2-byte length
        } else {
            header_offset += 1;  // 1-byte length
        }
        
        if (alp_len > header_offset + 20) {
            uint8_t version_ihl = alp_data[header_offset];
            
            if ((version_ihl >> 4) == 4) {
                uint16_t ip_total_length = ntohs(*(uint16_t*)(alp_data + header_offset + 2));
                
                if (header_offset + ip_total_length <= alp_len) {
                    *ip_payload = alp_data + header_offset;
                    *ip_len = ip_total_length;
                    return 0;
                }
            }
        }
    } else if (packet_type == 4) {
        // Link Layer Signaling packet
        //printf("DEBUG ALP: Found Link Layer Signaling packet (type 4)\n");
        
        int signaling_offset = 2;
        if (alp_len > signaling_offset) {
            *signaling_payload = alp_data + signaling_offset;
            *signaling_len = alp_len - signaling_offset;
            //printf("DEBUG ALP: Extracted signaling payload, %d bytes\n", *signaling_len);
            return 1;
        }
    } else {
        // Try to process any non-IPv4 packet as potential signaling
        //printf("DEBUG ALP: Unknown packet type %d, treating as potential signaling\n", packet_type);
        
        int signaling_offset = 1; // Try different offset
        if (alp_len > signaling_offset) {
            *signaling_payload = alp_data + signaling_offset;
            *signaling_len = alp_len - signaling_offset;
            //printf("DEBUG ALP: Extracted potential signaling payload, %d bytes\n", *signaling_len);
            return 1;
        }
    }
    
    return -1;
}
