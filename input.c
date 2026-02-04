/**
 * input.c - STLTP to ALP Depacketizer
 * 
 * Complete implementation based on libatsc3 architecture for processing
 * ATSC 3.0 STLTP (Studio-Transmitter Link Tunnel Protocol) PCAP files
 * and extracting ALP (ATSC Link-layer Protocol) packets.
 * 
 * Version: 2025-01-20-v13 (Added DUMP_BBP_START/END for raw BBP inspection)
 */

#include "input.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <time.h>
#include <strings.h>
#include <stdint.h>
#include <stdbool.h>

// ============================================================================
// Constants
// ============================================================================

#define MAX_PLPS                    64
#define MAX_ALP_PACKET_SIZE         65535
#define CARRYOVER_MAX_SIZE          65536
#define REASSEMBLY_BUFFER_SIZE      (512 * 1024)

// ============================================================================
// Debug Control
// ============================================================================

static int g_verbose = 0;
static int g_diag = 0;
static FILE* g_diag_out = NULL;

#define DIAG(...) do { if (g_diag && g_diag_out) fprintf(g_diag_out, __VA_ARGS__); } while(0)
#define VERBOSE(...) do { if (g_verbose) printf(__VA_ARGS__); } while(0)

// ============================================================================
// Base64 encoding
// ============================================================================

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char* base64_encode(const uint8_t *data, size_t input_length, size_t *output_length) {
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (!encoded_data) return NULL;
    
    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = base64_table[triple & 0x3F];
    }
    
    int mod = input_length % 3;
    if (mod == 1) {
        encoded_data[*output_length - 1] = '=';
        encoded_data[*output_length - 2] = '=';
    } else if (mod == 2) {
        encoded_data[*output_length - 1] = '=';
    }
    
    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// ============================================================================
// ALP Header Parsing - Matches A/330 exactly
// ============================================================================

/**
 * Parse ALP packet header to determine total packet length.
 * 
 * Returns: total packet length (header + payload), or 0 on error
 * Sets *header_len to the header size
 * Sets *payload_len to the payload size
 * 
 * Per A/330:
 * - Type 0 (IPv4): [type(3)|PC(1)|HM(1)|len(11)]
 * - Type 4 (Signaling): Same structure as Type 0
 * - Type 2 (Compressed IP): [type(3)|PC(1)|context(4)|len(11)] 
 * - Type 6 (Extension): [type(3)|reserved(4)|HEF(1)][len(16)]
 * - Type 7 (MPEG-TS): [type(3)|PC(1)|HDME(1)|NUMTS(3)]
 */
static size_t alp_get_packet_length(const uint8_t* data, size_t available,
                                     size_t* header_len, size_t* payload_len) {
    if (available < 2) return 0;
    
    uint8_t byte0 = data[0];
    uint8_t byte1 = data[1];
    uint8_t packet_type = (byte0 >> 5) & 0x07;
    uint8_t pc = (byte0 >> 4) & 0x01;
    uint8_t bit3 = (byte0 >> 3) & 0x01;  // HM for type 0/4, HDME for type 7, etc
    
    size_t hlen = 0;
    size_t plen = 0;
    
    switch (packet_type) {
        case 0:  // IPv4
        case 4:  // Signaling (LLS)
        {
            // 11-bit length in bits[2:0] of byte0 and all of byte1
            uint16_t len11 = ((byte0 & 0x07) << 8) | byte1;
            plen = len11;
            
            if (pc == 0) {
                // Single packet mode
                if (bit3 == 0) {
                    // HM=0: No additional header, 11-bit length only
                    hlen = 2;
                } else {
                    // HM=1: Has single_packet_header (at least 1 byte)
                    // single_packet_header format:
                    //   bits 7-3: length_MSB (5 bits, extends to 16-bit length)
                    //   bit 2: reserved (should be 1)
                    //   bit 1: SIF (sub_stream_identification_flag)
                    //   bit 0: HEF (header_extension_flag)
                    if (available < 3) return 0;
                    hlen = 3;
                    
                    uint8_t sph = data[2];
                    uint8_t length_msb = (sph >> 3) & 0x1F;  // 5-bit extension
                    uint8_t sif = (sph >> 1) & 0x01;
                    uint8_t hef = sph & 0x01;
                    
                    // Combine for 16-bit length: length_MSB(5) | len11(11)
                    plen = ((uint32_t)length_msb << 11) | len11;
                    
                    if (sif) hlen++;  // SID byte
                    
                    if (hef && available >= hlen + 2) {
                        // Header extension: ext_type(1) + ext_len(1) + ext_bytes
                        uint8_t ext_len = data[hlen + 1];
                        hlen += 2 + ext_len;
                    }
                }
            } else {
                // PC=1: Segmentation or Concatenation
                if (available < 3) return 0;
                hlen = 3;
                
                uint8_t seg_concat = bit3;
                if (seg_concat == 0) {
                    // Segmentation header
                    uint8_t seg_hdr = data[2];
                    uint8_t sif = (seg_hdr >> 1) & 0x01;
                    uint8_t hef = seg_hdr & 0x01;
                    
                    if (sif) hlen++;
                    if (hef && available >= hlen + 2) {
                        uint8_t ext_len = data[hlen + 1];
                        hlen += 2 + ext_len;
                    }
                } else {
                    // Concatenation header (complex - just use base)
                    // [length_MSB(4)|count_minus_2(3)|SIF(1)]
                    if (available < 4) return 0;
                    uint8_t count_minus_2 = (data[2] >> 1) & 0x07;
                    uint8_t sif = data[2] & 0x01;
                    int count = count_minus_2 + 2;
                    
                    // Each component has 12-bit length
                    int extra_bits = count * 12;
                    int extra_bytes = (extra_bits + 7) / 8;
                    hlen = 3 + extra_bytes;
                    if (sif) hlen++;
                    
                    // Use the combined length field
                    uint8_t len_msb = (data[2] >> 4) & 0x0F;
                    plen = (len_msb << 11) | len11;
                }
            }
            
            // For signaling packets (type 4), the length field specifies the
            // payload length AFTER the 5-byte signaling info header.
            // So total packet = 2 (ALP hdr) + 5 (sig info) + plen
            if (packet_type == 4) {
                hlen = 2 + 5;  // ALP header + signaling info header
                // plen stays the same - it's the actual signaling data length
            }
            break;
        }
        
        case 2:  // Compressed IP (ROHC)
        {
            // Similar to type 0 but with context_id in bit3
            uint16_t len11 = ((byte0 & 0x07) << 8) | byte1;
            hlen = 2;
            plen = len11;
            break;
        }
        
        case 6:  // Extension packet type
        {
            if (available < 3) return 0;
            // 16-bit length in bytes 1-2
            uint16_t len16 = (data[1] << 8) | data[2];
            uint8_t hef = byte0 & 0x01;
            hlen = 3;
            if (hef && available >= 5) {
                uint8_t ext_len = data[4];
                hlen += 2 + ext_len;
            }
            plen = len16;
            break;
        }
        
        case 7:  // MPEG-TS
        {
            if (pc == 1) {
                // Packetized TS
                uint16_t len11 = ((byte0 & 0x07) << 8) | byte1;
                hlen = 2;
                plen = len11;
            } else {
                // Direct TS packets
                uint8_t numts = (byte0 & 0x07) + 1;  // 1-8 packets
                hlen = bit3 ? 2 : 1;  // HDME determines header size
                plen = numts * 188;
            }
            break;
        }
        
        case 1:
        case 3:
        case 5:
            // Reserved types - likely sync error
            return 0;
    }
    
    if (header_len) *header_len = hlen;
    if (payload_len) *payload_len = plen;
    
    return hlen + plen;
}

// ============================================================================
// Per-PLP State for ALP reassembly
// ============================================================================

typedef struct {
    // Pending ALP packet (started in previous BBP, not yet complete)
    uint8_t* pending_data;
    size_t pending_size;       // Current accumulated size
    size_t pending_expected;   // Expected total size (0 if unknown)
    size_t pending_header_len; // Header length of pending packet
    
    // Short fragment at end of BBP (less than a complete ALP header)
    uint8_t* short_frag;
    size_t short_frag_size;
    
    // Debug tracking for spanning packets
    uint32_t pending_start_bbp;   // BBP number where this packet started
    uint32_t pending_cont_count;  // Number of continuation BBPs
} plp_alp_state_t;

// Per-PLP BBP reassembly state (for multi-RTP-packet BBPs)
typedef struct {
    uint8_t* buf;
    size_t size;
    size_t expected;
    bool active;
} plp_bbp_state_t;

// ============================================================================
// Depacketizer Context
// ============================================================================

typedef struct {
    plp_alp_state_t plp[MAX_PLPS];
    
    // Per-PLP BBP reassembly (for multi-RTP-packet BBPs)
    plp_bbp_state_t bbp[MAX_PLPS];
    
    // Preamble reassembly
    uint8_t* preamble_buf;
    size_t preamble_size;
    bool preamble_active;
    
    // T&M reassembly  
    uint8_t* tm_buf;
    size_t tm_size;
    bool tm_active;
    
    // Output
    uint8_t* out_alp;
    size_t out_alp_size;
    size_t out_alp_capacity;
    uint32_t out_alp_count;
    
    // Per-type counters
    uint32_t alp_type_counts[8];
    
    // L1
    uint8_t l1_basic[32];
    size_t l1_basic_size;
    uint8_t* l1_detail;
    size_t l1_detail_size;
    size_t l1_detail_capacity;
    
    // Stats
    uint32_t outer_pkts;
    uint32_t bbp_count;
    uint32_t preamble_count;
    uint32_t tm_count;
    uint32_t sync_errors;
    uint32_t spanning_complete;
    uint32_t rejected_packets;
    
    // Additional spanning packet stats
    uint32_t spanning_started;
    uint32_t spanning_discarded;
    uint32_t orphan_continuations;
    
    // RTP sequence tracking for gap detection
    uint16_t last_outer_seq;
    int outer_seq_valid;
    uint32_t outer_seq_gaps;
    uint32_t outer_seq_gap_packets;  // Estimated number of lost packets
    
    // Current packet output context (for debugging)
    struct {
        int plp;
        uint32_t bbp_num;
        uint32_t start_bbp;     // For spanning packets
        uint32_t cont_count;    // Number of continuation BBPs
        int is_spanning;        // 1 if from spanning reassembly
        const char* region;     // "post-ptr", "pre-ptr", "ptr=max"
    } pkt_source;
} depack_ctx_t;

// Debug trace environment variables
static uint32_t g_trace_dest_ip = 0;   // Set via TRACE_DEST_IP env var
static uint16_t g_trace_dest_port = 0; // Set via TRACE_DEST_PORT env var
static uint32_t g_trace_tsi = 0;       // Set via TRACE_TSI env var
static int g_trace_tsi_set = 0;        // Whether TSI filter is active

// Extract TSI from LCT header in UDP payload
// Returns TSI or 0 if not parseable
static uint32_t extract_tsi_from_lct(const uint8_t* udp_payload, size_t udp_len) {
    if (udp_len < 4) return 0;  // Need at least LCT base header
    
    // LCT header format (RFC 5651):
    // Byte 0: V(4) | C(2) | r(2)
    // Byte 1: S(1) | O(2) | H(1) | T(1) | R(1) | A(1) | B(1)
    // Byte 2: HDR_LEN (header length in 32-bit words)
    // Byte 3: CP (codepoint)
    // Then: CCI (length = 32*(C+1) bits = 4*(C+1) bytes)
    // Then: TSI (length = 32*S + 16*H bits)
    // Then: TOI (length = 32*O + 16*H bits)
    
    uint8_t version = (udp_payload[0] >> 4) & 0x0F;
    if (version != 1) return 0;  // LCT version should be 1
    
    uint8_t c_flag = (udp_payload[0] >> 2) & 0x03;  // CCI size indicator
    uint8_t s_flag = (udp_payload[1] >> 7) & 0x01;  // TSI present/size
    uint8_t h_flag = (udp_payload[1] >> 4) & 0x01;  // Half-word flag
    
    // CCI length in bytes: 4*(C+1)
    size_t cci_len = 4 * (c_flag + 1);
    
    // TSI starts after base header (4 bytes) + CCI
    size_t tsi_offset = 4 + cci_len;
    
    // TSI length: 32*S + 16*H bits = 4*S + 2*H bytes
    size_t tsi_len = 4 * s_flag + 2 * h_flag;
    
    if (tsi_len == 0) return 0;  // No TSI field present
    if (udp_len < tsi_offset + tsi_len) return 0;
    
    // Extract TSI based on length
    const uint8_t* tsi_ptr = udp_payload + tsi_offset;
    if (tsi_len == 2) {
        // 16-bit TSI (S=0, H=1)
        return (tsi_ptr[0] << 8) | tsi_ptr[1];
    } else if (tsi_len == 4) {
        // 32-bit TSI (S=1, H=0)
        return (tsi_ptr[0] << 24) | (tsi_ptr[1] << 16) | 
               (tsi_ptr[2] << 8) | tsi_ptr[3];
    } else if (tsi_len == 6) {
        // 48-bit TSI (S=1, H=1) - return lower 32 bits
        return (tsi_ptr[2] << 24) | (tsi_ptr[3] << 16) | 
               (tsi_ptr[4] << 8) | tsi_ptr[5];
    }
    
    return 0;
}

// BBP dump range for detailed debugging
static uint32_t g_dump_bbp_start = 0;
static uint32_t g_dump_bbp_end = 0;

static void init_trace_config(void) {
    static int initialized = 0;
    if (initialized) return;
    initialized = 1;
    
    const char* trace_ip = getenv("TRACE_DEST_IP");
    const char* trace_port = getenv("TRACE_DEST_PORT");
    const char* trace_tsi = getenv("TRACE_TSI");
    const char* dump_bbp_start = getenv("DUMP_BBP_START");
    const char* dump_bbp_end = getenv("DUMP_BBP_END");
    
    if (trace_ip) {
        // Parse dotted decimal IP
        unsigned int a, b, c, d;
        if (sscanf(trace_ip, "%u.%u.%u.%u", &a, &b, &c, &d) == 4) {
            g_trace_dest_ip = (a << 24) | (b << 16) | (c << 8) | d;
            printf("TRACE: Will trace packets to IP %s\n", trace_ip);
        }
    }
    if (trace_port) {
        g_trace_dest_port = (uint16_t)atoi(trace_port);
        printf("TRACE: Will trace packets to port %u\n", g_trace_dest_port);
    }
    if (trace_tsi) {
        g_trace_tsi = (uint32_t)strtoul(trace_tsi, NULL, 0);  // Supports hex with 0x prefix
        g_trace_tsi_set = 1;
        printf("TRACE: Will trace packets with TSI %u (0x%x)\n", g_trace_tsi, g_trace_tsi);
    }
    
    if (dump_bbp_start && dump_bbp_end) {
        g_dump_bbp_start = (uint32_t)strtoul(dump_bbp_start, NULL, 0);
        g_dump_bbp_end = (uint32_t)strtoul(dump_bbp_end, NULL, 0);
        printf("DUMP: Will dump raw BBP data for BBPs %u through %u\n", g_dump_bbp_start, g_dump_bbp_end);
    }
    
    // If any trace filter is set, also enable TSI dumping for first few packets
    if (g_trace_dest_ip != 0 || g_trace_dest_port != 0 || g_trace_tsi_set) {
        printf("TRACE: Will dump TSIs from first 20 unique streams seen\n");
    }
}

// Track unique TSIs seen for debugging
static uint32_t g_seen_tsis[100];
static int g_seen_tsi_count = 0;
static uint32_t g_trace_checked = 0;
static uint32_t g_trace_matched = 0;

// Check if we should trace this packet
static int should_trace_packet(const uint8_t* ip_header, size_t ip_len) {
    if (g_trace_dest_ip == 0 && g_trace_dest_port == 0 && !g_trace_tsi_set) return 0;
    if (ip_len < 24) return 0;  // Need at least IP header + UDP ports
    
    g_trace_checked++;
    
    uint32_t dest_ip = (ip_header[16] << 24) | (ip_header[17] << 16) | 
                       (ip_header[18] << 8) | ip_header[19];
    
    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
    if (ip_len < (size_t)(ihl + 4)) return 0;
    
    uint16_t dest_port = (ip_header[ihl + 2] << 8) | ip_header[ihl + 3];
    
    // Extract TSI for debugging/filtering
    size_t udp_payload_offset = ihl + 8;
    uint32_t tsi = 0;
    if (ip_len > udp_payload_offset) {
        const uint8_t* udp_payload = ip_header + udp_payload_offset;
        size_t udp_payload_len = ip_len - udp_payload_offset;
        tsi = extract_tsi_from_lct(udp_payload, udp_payload_len);
        
        // Track unique TSIs seen (for debugging)
        if (g_seen_tsi_count < 20) {
            int found = 0;
            for (int i = 0; i < g_seen_tsi_count; i++) {
                if (g_seen_tsis[i] == tsi) { found = 1; break; }
            }
            if (!found && g_seen_tsi_count < 100) {
                g_seen_tsis[g_seen_tsi_count++] = tsi;
                printf("TRACE: Saw TSI %u (0x%x) -> %d.%d.%d.%d:%d\n",
                        tsi, tsi,
                        ip_header[16], ip_header[17], ip_header[18], ip_header[19], dest_port);
            }
        }
    }
    
    // Check IP filter
    if (g_trace_dest_ip != 0 && dest_ip != g_trace_dest_ip) return 0;
    
    // Check port filter
    if (g_trace_dest_port != 0 && dest_port != g_trace_dest_port) return 0;
    
    // Check TSI filter
    if (g_trace_tsi_set && tsi != g_trace_tsi) return 0;
    
    g_trace_matched++;
    return 1;
}

// Get TSI for display (helper for trace output)
static uint32_t get_packet_tsi(const uint8_t* ip_header, size_t ip_len) {
    uint8_t ihl = (ip_header[0] & 0x0F) * 4;
    size_t udp_payload_offset = ihl + 8;
    if (ip_len <= udp_payload_offset) return 0;
    
    return extract_tsi_from_lct(ip_header + udp_payload_offset, ip_len - udp_payload_offset);
}

static depack_ctx_t* depack_new(void) {
    depack_ctx_t* ctx = calloc(1, sizeof(depack_ctx_t));
    if (!ctx) return NULL;
    
    ctx->preamble_buf = malloc(64 * 1024);
    ctx->tm_buf = malloc(64 * 1024);
    
    ctx->out_alp_capacity = 16 * 1024 * 1024;
    ctx->out_alp = malloc(ctx->out_alp_capacity);
    
    ctx->l1_detail_capacity = 8192;
    ctx->l1_detail = malloc(ctx->l1_detail_capacity);
    
    for (int i = 0; i < MAX_PLPS; i++) {
        ctx->plp[i].pending_data = malloc(CARRYOVER_MAX_SIZE);
        ctx->plp[i].short_frag = malloc(256);
        ctx->bbp[i].buf = malloc(REASSEMBLY_BUFFER_SIZE);
    }
    
    return ctx;
}

static void depack_free(depack_ctx_t* ctx) {
    if (!ctx) return;
    
    free(ctx->preamble_buf);
    free(ctx->tm_buf);
    free(ctx->out_alp);
    free(ctx->l1_detail);
    
    for (int i = 0; i < MAX_PLPS; i++) {
        free(ctx->plp[i].pending_data);
        free(ctx->plp[i].short_frag);
        free(ctx->bbp[i].buf);
    }
    
    free(ctx);
}

// ============================================================================
// Output an ALP packet (write to output buffer)
// ============================================================================

static void output_alp_packet(depack_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (len < 2 || len > MAX_ALP_PACKET_SIZE) {
        static int bad_len_count = 0;
        if (bad_len_count < 10) {
            bad_len_count++;
            printf("\n=== REJECT ALP BAD LENGTH #%d ===\n", bad_len_count);
            printf("len=%zu, BBP #%u, region=%s\n", len,
                    ctx->pkt_source.bbp_num, ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            if (len > 0) {
                printf("First bytes: ");
                for (size_t i = 0; i < 16 && i < len; i++) {
                    printf("%02x ", data[i]);
                }
                printf("\n");
            }
            printf("================================\n\n");
        }
        ctx->rejected_packets++;
        return;
    }
    
    // Verify this looks like a valid ALP packet
    uint8_t type = (data[0] >> 5) & 0x07;
    if (type == 1 || type == 3 || type == 5) {
        // Reserved types - don't output
        static int reserved_reject_count = 0;
        if (reserved_reject_count < 10) {
            reserved_reject_count++;
            printf("\n=== REJECTED RESERVED TYPE #%d ===\n", reserved_reject_count);
            printf("Type: %d, len: %zu, BBP #%u, region=%s\n", type, len,
                    ctx->pkt_source.bbp_num, ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            if (ctx->pkt_source.is_spanning) {
                printf("Spanning from BBP #%u (%u conts)\n",
                        ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
            }
            printf("First 32 bytes: ");
            for (size_t i = 0; i < 32 && i < len; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n==================================\n\n");
        }
        ctx->rejected_packets++;
        return;
    }
    
    // For IPv4 packets (type 0), validate the IP header
    if (type == 0) {
        // Calculate header length to find IP payload
        size_t hlen, plen;
        size_t total = alp_get_packet_length(data, len, &hlen, &plen);
        
        if (total == 0) {
            static int len_reject_count = 0;
            if (len_reject_count < 10) {
                len_reject_count++;
                printf("\n=== REJECTED TYPE 0 BAD LENGTH #%d ===\n", len_reject_count);
                printf("total=%zu, len=%zu\n", total, len);
                printf("First 16 bytes: ");
                for (size_t i = 0; i < 16 && i < len; i++) {
                    printf("%02x ", data[i]);
                }
                printf("\n======================================\n\n");
            }
            ctx->rejected_packets++;
            return;
        }
        
        // Check IP header
        if (hlen < len && len - hlen >= 20) {
            const uint8_t* ip = data + hlen;
            uint8_t version = (ip[0] >> 4) & 0x0F;
            uint8_t ihl = ip[0] & 0x0F;
            
            if (version != 4 || ihl < 5) {
                static int ip_reject_count = 0;
                if (ip_reject_count < 10) {
                    ip_reject_count++;
                    printf("\n=== REJECTED TYPE 0 BAD IP #%d ===\n", ip_reject_count);
                    printf("version=%d, ihl=%d\n", version, ihl);
                    printf("ALP bytes: ");
                    for (size_t i = 0; i < hlen && i < 8; i++) {
                        printf("%02x ", data[i]);
                    }
                    printf("| IP bytes: ");
                    for (size_t i = 0; i < 16 && hlen + i < len; i++) {
                        printf("%02x ", ip[i]);
                    }
                    printf("\n==================================\n\n");
                }
                ctx->sync_errors++;
                ctx->rejected_packets++;
                return;
            }
            
            // Check destination IP is multicast (224.0.0.0 - 239.255.255.255)
            uint8_t dst_first_octet = ip[16];
            if (dst_first_octet < 224 || dst_first_octet > 239) {
                static int mcast_reject_count = 0;
                if (mcast_reject_count < 10) {
                    mcast_reject_count++;
                    printf("\n=== REJECTED TYPE 0 NON-MULTICAST #%d ===\n", mcast_reject_count);
                    printf("dst IP: %d.%d.%d.%d\n", ip[16], ip[17], ip[18], ip[19]);
                    printf("ALP header: %02x %02x (type=%d, len=%zu)\n",
                            data[0], data[1], type, total);
                    printf("IP header: ");
                    for (size_t i = 0; i < 20 && hlen + i < len; i++) {
                        printf("%02x ", ip[i]);
                    }
                    printf("\n=========================================\n\n");
                }
                ctx->sync_errors++;
                ctx->rejected_packets++;
                return;
            }
            
            // Validate IP total length makes sense
            uint16_t ip_total_len = (ip[2] << 8) | ip[3];
            if (ip_total_len < 20 || ip_total_len > plen) {
                static int iplen_reject_count = 0;
                if (iplen_reject_count < 10) {
                    iplen_reject_count++;
                    printf("\n=== REJECTED TYPE 0 BAD IP LEN #%d ===\n", iplen_reject_count);
                    printf("ip_total_len=%d, plen=%zu\n", ip_total_len, plen);
                    printf("First 20 bytes: ");
                    for (size_t i = 0; i < 20 && i < len; i++) {
                        printf("%02x ", data[i]);
                    }
                    printf("\n=====================================\n\n");
                }
                ctx->sync_errors++;
                ctx->rejected_packets++;
                return;
            }
        }
    }
    
    // For signaling packets (type 4), do basic sanity check
    if (type == 4) {
        size_t hlen, plen;
        size_t total = alp_get_packet_length(data, len, &hlen, &plen);
        if (total == 0 || plen < 2) {
            VERBOSE("  REJECT ALP type 4: signaling packet too small (total=%zu plen=%zu)\n", total, plen);
            ctx->rejected_packets++;
            return;
        }
        VERBOSE("  ACCEPT ALP type 4 (signaling): len=%zu hlen=%zu plen=%zu\n", len, hlen, plen);
        
        // Dump short type 4 packets (len < 64) - these are suspicious
        static int type4_short_dumped = 0;
        if (len < 64 && type4_short_dumped < 10) {
            type4_short_dumped++;
            printf("\n=== Short Type 4 Packet #%d ===\n", type4_short_dumped);
            printf("Total length: %zu, header: %zu, payload: %zu\n", len, hlen, plen);
            printf("All %zu bytes: ", len);
            for (size_t i = 0; i < len; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
            printf("================================\n\n");
        }
        
        // Dump first type 4 packet we see (for debugging LMT)
        static int type4_dumped = 0;
        if (!type4_dumped) {
            type4_dumped = 1;
            printf("\n=== First Type 4 (Signaling) Packet Hex Dump ===\n");
            printf("Total length: %zu, header: %zu, payload: %zu\n", len, hlen, plen);
            printf("Bytes: ");
            for (size_t i = 0; i < len && i < 64; i++) {
                printf("%02x ", data[i]);
                if ((i + 1) % 16 == 0) printf("\n       ");
            }
            if (len > 64) printf("... (%zu more bytes)", len - 64);
            printf("\n");
            
            // Parse signaling header (after ALP header)
            if (len > hlen + 1) {
                uint8_t sig_type = data[hlen];
                uint8_t sig_info = (len > hlen + 1) ? data[hlen + 1] : 0;
                printf("Signaling type byte: 0x%02x\n", sig_type);
                // For LLS, byte after header is table_id
                if ((sig_type & 0x01) == 0x01) {  // LLS indicator
                    uint8_t table_id = sig_info;
                    printf("LLS table_id: %d (0x%02x)\n", table_id, table_id);
                    if (table_id == 254) printf("*** This is LMT! ***\n");
                }
            }
            printf("=================================================\n\n");
        }
    }
    
    // Debug: After outputting type 4, show what would come next in the buffer
    // (This helps debug why type 7 follows)
    static int post_type4_debug = 0;
    if (type == 4 && !post_type4_debug) {
        post_type4_debug = 1;
        // We can't easily see what's next from here, but we'll add debug in the parsing loop
    }
    
    // Trace matching type 0 packets
    if (type == 0) {
        size_t hlen, plen;
        alp_get_packet_length(data, len, &hlen, &plen);
        if (hlen < len && should_trace_packet(data + hlen, len - hlen)) {
            const uint8_t* ip = data + hlen;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            uint16_t dest_port = (len > hlen + ihl + 4) ? (ip[ihl + 2] << 8) | ip[ihl + 3] : 0;
            uint16_t ip_total_len = (ip[2] << 8) | ip[3];
            uint32_t tsi = get_packet_tsi(ip, len - hlen);
            
            printf("\n=== TRACE: OUTPUT ALP PACKET ===\n");
            printf("Dest: %d.%d.%d.%d:%d, TSI: %u (0x%x)\n", 
                    ip[16], ip[17], ip[18], ip[19], dest_port, tsi, tsi);
            printf("ALP len=%zu (hlen=%zu, plen=%zu), IP total_len=%u\n", 
                    len, hlen, plen, ip_total_len);
            printf("Source: PLP %d, BBP #%u", ctx->pkt_source.plp, ctx->pkt_source.bbp_num);
            if (ctx->pkt_source.is_spanning) {
                printf(" (SPANNING from BBP #%u, %u continuations, region=%s)\n",
                        ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count,
                        ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            } else {
                printf(" (single-BBP, region=%s)\n",
                        ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            }
            
            // Show packet structure
            printf("ALP header: ");
            for (size_t i = 0; i < hlen && i < 8; i++) printf("%02x ", data[i]);
            printf("\nIP header: ");
            for (size_t i = 0; i < 20 && hlen + i < len; i++) printf("%02x ", ip[i]);
            printf("\nUDP header+payload start: ");
            for (size_t i = ihl; i < ihl + 32 && hlen + i < len; i++) printf("%02x ", ip[i]);
            printf("\n");
            
            // Check for truncation
            if (ip_total_len != plen) {
                printf("*** WARNING: IP total_len (%u) != ALP plen (%zu) ***\n", ip_total_len, plen);
            }
            if (len < hlen + ip_total_len) {
                printf("*** WARNING: Packet truncated! Have %zu bytes, IP says %zu ***\n",
                        len, hlen + ip_total_len);
            }
            printf("=================================\n\n");
        }
    }
    
    // Ensure capacity
    if (ctx->out_alp_size + len > ctx->out_alp_capacity) {
        size_t new_cap = ctx->out_alp_capacity * 2;
        uint8_t* new_buf = realloc(ctx->out_alp, new_cap);
        if (!new_buf) return;
        ctx->out_alp = new_buf;
        ctx->out_alp_capacity = new_cap;
    }
    
    // Debug: dump unexpected packet types that shouldn't be in this stream
    if (type == 2 || type == 6 || type == 7) {
        static int unexpected_type_count = 0;
        if (unexpected_type_count < 20) {
            unexpected_type_count++;
            printf("\n=== UNEXPECTED ALP TYPE %d (#%d) ===\n", type, unexpected_type_count);
            printf("BBP #%u, PLP %d, region=%s\n", 
                    ctx->pkt_source.bbp_num, ctx->pkt_source.plp,
                    ctx->pkt_source.region ? ctx->pkt_source.region : "?");
            if (ctx->pkt_source.is_spanning) {
                printf("Spanning from BBP #%u (%u continuations)\n",
                        ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
            }
            printf("Packet len=%zu, first 32 bytes:\n", len);
            for (size_t i = 0; i < 32 && i < len; i++) {
                printf("%02x ", data[i]);
            }
            printf("\n");
            // Also show what the ALP header decodes to
            if (len >= 2) {
                uint8_t b0 = data[0], b1 = data[1];
                printf("ALP decode: type=%d PC=%d HM/bit3=%d len_msb=%d len_lsb=%d\n",
                        (b0 >> 5) & 0x07, (b0 >> 4) & 0x01, (b0 >> 3) & 0x01,
                        b0 & 0x07, b1);
                printf("11-bit length = %d\n", ((b0 & 0x07) << 8) | b1);
            }
            printf("=====================================\n\n");
        }
    }
    
    memcpy(ctx->out_alp + ctx->out_alp_size, data, len);
    ctx->out_alp_size += len;
    ctx->out_alp_count++;
    ctx->alp_type_counts[type]++;
    
    if (ctx->pkt_source.is_spanning) {
        VERBOSE("  OUTPUT ALP: BBP #%u type=%d len=%zu total=%u (spanning from #%u, %u conts)\n", 
                ctx->pkt_source.bbp_num, type, len, ctx->out_alp_count,
                ctx->pkt_source.start_bbp, ctx->pkt_source.cont_count);
    } else {
        VERBOSE("  OUTPUT ALP: BBP #%u type=%d len=%zu total=%u\n", 
                ctx->pkt_source.bbp_num, type, len, ctx->out_alp_count);
    }
}

// ============================================================================
// Process Baseband Packet - Extract ALP packets
// ============================================================================

/**
 * Process a complete Baseband Packet and extract ALP packets.
 * 
 * Per A/322 Section 5.2:
 * - BBP header contains pointer to first NEW ALP packet
 * - Bytes before pointer are continuation of previous ALP packet
 * - Pointer = max (127 or 8191) means no new ALP packet starts
 * 
 * BBP Header structure per A/322 Section 5.2.2:
 * Mode 0 (1 byte): [mode=0(1)][pointer(7)]
 * Mode 1 (2+ bytes): [mode=1(1)][pointer_lsb(7)] [pointer_msb(6)][OFI(2)]
 *   OFI=00: No extension
 *   OFI=01: Short ext [ext_type(3)][ext_len(5)] + ext_len bytes
 *   OFI=10: Long ext [ext_type(3)][ext_len_lsb(5)][ext_len_msb(8)] + ext_len bytes
 *   OFI=11: Mixed ext [num_ext(3)][ext_len_lsb(5)][ext_len_msb(8)] + ext_len bytes
 */
static void process_bbp(depack_ctx_t* ctx, int plp, const uint8_t* data, size_t len) {
    if (len < 1 || plp < 0 || plp >= MAX_PLPS) return;
    
    // Sanity check: BBP should NOT start with IP header (0x45)
    // If we see this, something is wrong with the tunnel parsing
    if (len > 20 && data[0] == 0x45) {
        printf("ERROR: BBP data starts with 0x45 (IP header?) - possible tunnel parse error\n");
        printf("  First 20 bytes: ");
        for (int i = 0; i < 20 && (size_t)i < len; i++) printf("%02x ", data[i]);
        printf("\n");
        return;
    }
    
    ctx->bbp_count++;
    plp_alp_state_t* st = &ctx->plp[plp];
    
    // Detailed BBP dump for debugging
    int do_dump = (g_dump_bbp_start > 0 && g_dump_bbp_end > 0 &&
                   ctx->bbp_count >= g_dump_bbp_start && ctx->bbp_count <= g_dump_bbp_end);
    
    if (do_dump) {
        printf("\n");
        printf("================================================================================\n");
        printf("BBP #%u RAW DUMP (PLP %d, len=%zu)\n", ctx->bbp_count, plp, len);
        printf("================================================================================\n");
        
        // State before processing
        printf("PENDING STATE BEFORE:\n");
        printf("  pending_size=%zu, pending_expected=%zu\n", st->pending_size, st->pending_expected);
        if (st->pending_size > 0 && st->pending_expected > 0) {
            printf("  need %zu more bytes to complete\n", st->pending_expected - st->pending_size);
            printf("  started at BBP #%u\n", st->pending_start_bbp);
        }
        printf("\n");
        
        // Raw header bytes (first 16)
        printf("RAW HEADER (first 16 bytes):\n  ");
        for (size_t i = 0; i < 16 && i < len; i++) {
            printf("%02x ", data[i]);
        }
        printf("\n\n");
        
        // Full raw dump - complete
        printf("RAW DATA (%zu bytes):\n", len);
        for (size_t i = 0; i < len; i++) {
            if (i % 32 == 0) printf("  %04zx: ", i);
            printf("%02x ", data[i]);
            if ((i + 1) % 32 == 0) printf("\n");
        }
        if (len % 32 != 0) printf("\n");
        printf("\n");
    }
    
    const uint8_t* p = data;
    size_t remaining = len;
    
    // Track extension info for debugging discards
    uint8_t bbp_ext_type = 0;
    uint16_t bbp_ext_len = 0;
    const uint8_t* bbp_ext_data = NULL;
    
    // Parse base field byte 0
    uint8_t b0 = *p++;
    remaining--;
    
    uint8_t mode = (b0 >> 7) & 0x01;
    uint16_t pointer = b0 & 0x7F;
    uint16_t max_ptr;
    
    if (mode == 0) {
        // Mode 0: 7-bit pointer, 1 byte header total
        max_ptr = 0x7F;
    } else {
        // Mode 1: 13-bit pointer, at least 2 bytes header
        if (remaining < 1) return;
        uint8_t b1 = *p++;
        remaining--;
        
        pointer |= ((b1 >> 2) & 0x3F) << 7;
        max_ptr = 0x1FFF;  // 8191
        
        uint8_t ofi = b1 & 0x03;
        
        // Handle optional extension field
        if (ofi != 0x00) {
            if (remaining < 1) return;
            uint8_t ext_byte0 = *p++;
            remaining--;
            
            uint8_t ext_type = (ext_byte0 >> 5) & 0x07;
            uint16_t ext_len = ext_byte0 & 0x1F;
            
            if (ofi == 0x02 || ofi == 0x03) {
                // Long or Mixed extension mode - 13-bit ext_len
                if (remaining < 1) return;
                uint8_t ext_byte1 = *p++;
                remaining--;
                ext_len |= (ext_byte1 << 5);
            }
            
            // Save extension info for discard debugging
            bbp_ext_type = ext_type;
            bbp_ext_len = ext_len;
            bbp_ext_data = p;  // Points to extension content
            
            // Sanity check: extension length should not be larger than remaining payload
            // If it is, the header is likely corrupt - skip extensions
            if (ext_len > remaining) {
                VERBOSE("  BBP: ext_len %u > remaining %zu, ignoring extension (likely corrupt)\n", 
                        ext_len, remaining);
                // Don't skip - treat remaining as payload
            } else if (ext_len > 0) {
                // Debug: verify padding extension content
                static int ext_debug_count = 0;
                if (ext_type == 7 && ext_len > 100 && ext_debug_count < 3) {
                    ext_debug_count++;
                    printf("\n=== BBP Extension Debug #%d ===\n", ext_debug_count);
                    printf("ext_type=%d (padding), ext_len=%u\n", ext_type, ext_len);
                    
                    // Count how many 0x00 bytes vs non-zero
                    size_t zero_count = 0;
                    size_t nonzero_count = 0;
                    for (size_t i = 0; i < ext_len && i < remaining; i++) {
                        if (p[i] == 0x00) zero_count++;
                        else nonzero_count++;
                    }
                    printf("Content: %zu zeros, %zu non-zeros\n", zero_count, nonzero_count);
                    
                    // Show first 32 bytes
                    printf("First 32 bytes: ");
                    for (size_t i = 0; i < 32 && i < ext_len && i < remaining; i++) {
                        printf("%02x ", p[i]);
                    }
                    printf("\n");
                    
                    // Show last 32 bytes
                    if (ext_len > 64) {
                        printf("Last 32 bytes:  ");
                        size_t start = (ext_len < remaining ? ext_len : remaining) - 32;
                        for (size_t i = 0; i < 32; i++) {
                            printf("%02x ", p[start + i]);
                        }
                        printf("\n");
                    }
                    printf("================================\n\n");
                }
                
                // Skip extension bytes
                // ext_type=7 means padding
                p += ext_len;
                remaining -= ext_len;
            }
            
            (void)ext_type;  // We just skip extension data for now
        }
    }
    
    // p now points to payload, remaining is payload length
    const uint8_t* payload = p;
    size_t payload_len = remaining;
    
    // Debug: show BBP header bytes for cases with warnings
    size_t hdr_len = p - data;
    
    // Detailed dump: show our interpretation
    if (do_dump) {
        printf("HEADER INTERPRETATION:\n");
        printf("  mode=%d, pointer=%u (0x%x), max_ptr=%u\n", mode, pointer, pointer, max_ptr);
        printf("  header_len=%zu, payload_len=%zu\n", hdr_len, payload_len);
        if (bbp_ext_len > 0) {
            printf("  extension: type=%d, len=%u\n", bbp_ext_type, bbp_ext_len);
        }
        printf("\n");
        
        printf("PAYLOAD REGIONS:\n");
        if (pointer == max_ptr) {
            printf("  pointer=max: entire payload (%zu bytes) is continuation\n", payload_len);
        } else {
            printf("  pre-pointer region: bytes 0-%u (%u bytes)\n", pointer > 0 ? pointer-1 : 0, pointer);
            printf("  post-pointer region: bytes %u-%zu (%zu bytes)\n", pointer, payload_len-1, payload_len - pointer);
        }
        printf("\n");
        
        // Show pre-pointer region content
        if (pointer > 0 && pointer != max_ptr) {
            printf("PRE-POINTER REGION (%u bytes):\n", pointer);
            for (size_t i = 0; i < pointer && i < payload_len; i++) {
                if (i % 32 == 0) printf("  %04zx: ", i);
                printf("%02x ", payload[i]);
                if ((i + 1) % 32 == 0) printf("\n");
            }
            if (pointer % 32 != 0) printf("\n");
            printf("\n");
        }
        
        // Show post-pointer region content
        if (pointer < payload_len) {
            size_t post_len = payload_len - pointer;
            printf("POST-POINTER REGION (%zu bytes):\n", post_len);
            for (size_t i = 0; i < post_len; i++) {
                if (i % 32 == 0) printf("  %04zx: ", pointer + i);
                printf("%02x ", payload[pointer + i]);
                if ((i + 1) % 32 == 0) printf("\n");
            }
            if (post_len % 32 != 0) printf("\n");
            printf("\n");
        }
        
        printf("--------------------------------------------------------------------------------\n");
    }
    
    if (g_verbose) {
        printf("BBP #%u PLP%d: len=%zu mode=%d ptr=%u payload=%zu pending=%zu (hdr=%zu bytes: ",
                ctx->bbp_count, plp, len, mode, pointer, payload_len, st->pending_size, hdr_len);
        for (size_t i = 0; i < hdr_len && i < 8; i++) {
            printf("%02x ", data[i]);
        }
        printf(")\n");
    } else {
        VERBOSE("BBP #%u PLP%d: len=%zu mode=%d ptr=%u payload=%zu pending=%zu\n",
                ctx->bbp_count, plp, len, mode, pointer, payload_len, st->pending_size);
    }
    
    // Case 1: Pointer = max -> entire payload is continuation
    if (pointer == max_ptr) {
        if (st->pending_size > 0 && st->pending_expected > 0) {
            size_t need = st->pending_expected - st->pending_size;
            size_t copy = (payload_len < need) ? payload_len : need;
            memcpy(st->pending_data + st->pending_size, payload, copy);
            st->pending_size += copy;
            st->pending_cont_count++;
            
            if (st->pending_size >= st->pending_expected) {
                // Debug: check if this is an LLS packet completing
                uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
                if (pkt_type == 0 && st->pending_expected > 22) {
                    size_t hlen_chk, plen_chk;
                    alp_get_packet_length(st->pending_data, st->pending_expected, &hlen_chk, &plen_chk);
                    if (hlen_chk + 19 < st->pending_expected) {
                        const uint8_t* ip = st->pending_data + hlen_chk;
                        if (ip[16] == 224 && ip[17] == 0 && ip[18] == 23 && ip[19] == 60) {
                            printf("\n=== LLS SPANNING PACKET COMPLETE (ptr=max) ===\n");
                            printf("Started BBP #%u, completed BBP #%u (%u continuations)\n",
                                    st->pending_start_bbp, ctx->bbp_count, st->pending_cont_count);
                            printf("Total size: %zu bytes\n", st->pending_expected);
                            uint16_t ip_len = (ip[2] << 8) | ip[3];
                            printf("IP total_length field: %u\n", ip_len);
                            printf("Last 32 bytes: ");
                            size_t start = st->pending_expected > 32 ? st->pending_expected - 32 : 0;
                            for (size_t i = start; i < st->pending_expected; i++) {
                                printf("%02x ", st->pending_data[i]);
                            }
                            printf("\n");
                            // For ptr=max, remaining bytes after completing pending (if any)
                            size_t leftover = payload_len - copy;
                            if (leftover > 0) {
                                printf("Leftover %zu bytes after pending: ", leftover);
                                const uint8_t* left = payload + copy;
                                for (size_t i = 0; i < 32 && i < leftover; i++) {
                                    printf("%02x ", left[i]);
                                }
                                printf("\n");
                            } else {
                                printf("(ptr=max: no post-ptr in this BBP, next pkt in future BBP)\n");
                            }
                            printf("==============================================\n\n");
                        }
                    }
                }
                
                // Set packet source for tracing
                ctx->pkt_source.plp = plp;
                ctx->pkt_source.bbp_num = ctx->bbp_count;
                ctx->pkt_source.start_bbp = st->pending_start_bbp;
                ctx->pkt_source.cont_count = st->pending_cont_count;
                ctx->pkt_source.is_spanning = 1;
                ctx->pkt_source.region = "ptr=max";
                
                output_alp_packet(ctx, st->pending_data, st->pending_expected);
                ctx->spanning_complete++;
                st->pending_size = 0;
                st->pending_expected = 0;
            }
        } else if (payload_len > 0) {
            // No pending packet but we have continuation data - orphan
            ctx->orphan_continuations++;
            VERBOSE("  BBP #%u Orphan continuation (ptr=max): %zu bytes\n", ctx->bbp_count, payload_len);
        }
        return;
    }
    
    // Validate pointer
    if (pointer > payload_len) {
        VERBOSE("  ERROR: pointer %u > payload_len %zu, resetting state\n", pointer, payload_len);
        ctx->sync_errors++;
        st->pending_size = 0;
        st->pending_expected = 0;
        st->short_frag_size = 0;
        return;
    }
    
    // === Process Pre-Pointer Region (continuation bytes) ===
    if (pointer > 0) {
        const uint8_t* pre_ptr = payload;
        size_t pre_len = pointer;
        
        // First, prepend any short fragment from previous BBP
        uint8_t* region = NULL;
        size_t region_len = 0;
        bool free_region = false;
        
        if (st->short_frag_size > 0) {
            region_len = st->short_frag_size + pre_len;
            region = malloc(region_len);
            if (region) {
                memcpy(region, st->short_frag, st->short_frag_size);
                memcpy(region + st->short_frag_size, pre_ptr, pre_len);
                free_region = true;
            }
            st->short_frag_size = 0;
        } else {
            region = (uint8_t*)pre_ptr;
            region_len = pre_len;
        }
        
        if (st->pending_size > 0 && st->pending_expected > 0) {
            // We have a pending packet - append continuation bytes
            size_t need = st->pending_expected - st->pending_size;
            size_t copy = (region_len < need) ? region_len : need;
            
            VERBOSE("  BBP #%u Pre-pointer: %zu bytes, pending needs %zu more, copying %zu\n", 
                    ctx->bbp_count, region_len, need, copy);
            
            memcpy(st->pending_data + st->pending_size, region, copy);
            st->pending_size += copy;
            st->pending_cont_count++;
            
            if (st->pending_size >= st->pending_expected) {
                // Debug: check if this is an LLS packet completing
                uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
                if (pkt_type == 0 && st->pending_expected > 22) {
                    size_t hlen_chk, plen_chk;
                    alp_get_packet_length(st->pending_data, st->pending_expected, &hlen_chk, &plen_chk);
                    if (hlen_chk + 19 < st->pending_expected) {
                        const uint8_t* ip = st->pending_data + hlen_chk;
                        if (ip[16] == 224 && ip[17] == 0 && ip[18] == 23 && ip[19] == 60) {
                            printf("\n=== LLS SPANNING PACKET COMPLETE (pre-ptr) ===\n");
                            printf("Started BBP #%u, completed BBP #%u (%u continuations)\n",
                                    st->pending_start_bbp, ctx->bbp_count, st->pending_cont_count);
                            printf("Total size: %zu bytes\n", st->pending_expected);
                            uint16_t ip_len = (ip[2] << 8) | ip[3];
                            printf("IP total_length field: %u\n", ip_len);
                            printf("Last 32 bytes: ");
                            size_t start = st->pending_expected > 32 ? st->pending_expected - 32 : 0;
                            for (size_t i = start; i < st->pending_expected; i++) {
                                printf("%02x ", st->pending_data[i]);
                            }
                            printf("\n");
                            // Show next 32 bytes (start of post-pointer region)
                            const uint8_t* post_ptr = payload + pointer;
                            size_t post_len = payload_len - pointer;
                            printf("Next 32 bytes (post-ptr): ");
                            for (size_t i = 0; i < 32 && i < post_len; i++) {
                                printf("%02x ", post_ptr[i]);
                            }
                            if (post_len > 0) {
                                uint8_t next_type = (post_ptr[0] >> 5) & 0x07;
                                printf("\n  -> Next byte 0x%02x = type %d", post_ptr[0], next_type);
                            }
                            printf("\n==============================================\n\n");
                        }
                    }
                }
                
                // Packet complete!
                ctx->pkt_source.plp = plp;
                ctx->pkt_source.bbp_num = ctx->bbp_count;
                ctx->pkt_source.start_bbp = st->pending_start_bbp;
                ctx->pkt_source.cont_count = st->pending_cont_count;
                ctx->pkt_source.is_spanning = 1;
                ctx->pkt_source.region = "pre-ptr";
                
                output_alp_packet(ctx, st->pending_data, st->pending_expected);
                ctx->spanning_complete++;
                st->pending_size = 0;
                st->pending_expected = 0;
            }
            
            // Any remaining bytes in pre_ptr region after completing pending?
            // Per A/322, these are PADDING between end of continuation and the pointer.
            // Do NOT try to parse them as ALP packets.
            if (copy < region_len) {
                size_t padding_bytes = region_len - copy;
                VERBOSE("  BBP #%u Pre-ptr padding: %zu bytes (skipping)\n",
                        ctx->bbp_count, padding_bytes);
            }
        } else if (st->pending_size > 0) {
            // We have pending data but don't know expected length
            // Append and try to parse header
            size_t space = CARRYOVER_MAX_SIZE - st->pending_size;
            size_t copy = (region_len < space) ? region_len : space;
            memcpy(st->pending_data + st->pending_size, region, copy);
            st->pending_size += copy;
            
            // Try to determine length
            if (st->pending_size >= 2) {
                size_t hlen, plen;
                size_t total = alp_get_packet_length(st->pending_data, st->pending_size, &hlen, &plen);
                if (total > 0) {
                    st->pending_expected = total;
                    st->pending_header_len = hlen;
                    
                    if (st->pending_size >= total) {
                        ctx->pkt_source.plp = plp;
                        ctx->pkt_source.bbp_num = ctx->bbp_count;
                        ctx->pkt_source.start_bbp = st->pending_start_bbp;
                        ctx->pkt_source.cont_count = st->pending_cont_count;
                        ctx->pkt_source.is_spanning = 1;
                        ctx->pkt_source.region = "pre-ptr-deferred";
                        
                        output_alp_packet(ctx, st->pending_data, total);
                        ctx->spanning_complete++;
                        st->pending_size = 0;
                        st->pending_expected = 0;
                    }
                }
            }
        } else {
            // No pending packet - these are orphan continuation bytes
            // This happens at start of stream or after discontinuity
            VERBOSE("  BBP #%u Orphan continuation: %zu bytes (discarding)\n", ctx->bbp_count, region_len);
        }
        
        if (free_region) free(region);
    }
    
    // === Process Post-Pointer Region (new ALP packets) ===
    const uint8_t* post_ptr = payload + pointer;
    size_t post_len = payload_len - pointer;
    
    VERBOSE("  BBP #%u Post-pointer: %zu bytes at offset %u\n", ctx->bbp_count, post_len, pointer);
    
    // Debug: show first bytes of post-pointer after completing a spanning packet
    static int post_span_debug = 0;
    if (st->pending_size == 0 && st->pending_expected == 0 && post_span_debug < 5) {
        // We just completed a spanning packet (or had none)
        // Show what's at the start of post-pointer
        if (post_len > 0) {
            post_span_debug++;
            printf("  [DEBUG] Post-pointer first 20 bytes: ");
            for (size_t i = 0; i < 20 && i < post_len; i++) {
                printf("%02x ", post_ptr[i]);
            }
            printf("\n");
        }
    }
    
    // Prepend any short fragment from previous BBP
    uint8_t* work = NULL;
    size_t work_len = 0;
    bool free_work = false;
    
    if (st->short_frag_size > 0 && pointer == 0) {
        // Short frag applies to post-pointer only if pointer == 0
        work_len = st->short_frag_size + post_len;
        work = malloc(work_len);
        if (work) {
            memcpy(work, st->short_frag, st->short_frag_size);
            memcpy(work + st->short_frag_size, post_ptr, post_len);
            free_work = true;
        }
        st->short_frag_size = 0;
    } else {
        work = (uint8_t*)post_ptr;
        work_len = post_len;
    }
    
    // Clear any existing pending (new ALP packets start here)
    // If pending wasn't completed by pre-pointer region, it's a discontinuity
    if (st->pending_size > 0) {
        ctx->spanning_discarded++;
        
        // Check if this was an LLS packet being discarded
        uint8_t pkt_type = (st->pending_data[0] >> 5) & 0x07;
        bool is_lls = false;
        bool should_trace = false;
        
        if (pkt_type == 0 && st->pending_size > 22 && st->pending_header_len > 0) {
            const uint8_t* ip = st->pending_data + st->pending_header_len;
            if (st->pending_header_len + 19 < st->pending_size) {
                if (ip[16] == 224 && ip[17] == 0 && ip[18] == 23 && ip[19] == 60) {
                    is_lls = true;
                }
                should_trace = should_trace_packet(ip, st->pending_size - st->pending_header_len);
            }
        }
        
        if (is_lls) {
            printf("\n=== WARNING: DISCARDING INCOMPLETE LLS PACKET ===\n");
            printf("Started BBP #%u, discarding at BBP #%u\n", 
                    st->pending_start_bbp, ctx->bbp_count);
            printf("Had %zu of %zu expected bytes (%zu missing)\n",
                    st->pending_size, st->pending_expected, 
                    st->pending_expected - st->pending_size);
            printf("First 32 bytes: ");
            for (size_t i = 0; i < 32 && i < st->pending_size; i++) {
                printf("%02x ", st->pending_data[i]);
            }
            printf("\n=================================================\n\n");
        } else if (should_trace) {
            const uint8_t* ip = st->pending_data + st->pending_header_len;
            uint8_t ihl = (ip[0] & 0x0F) * 4;
            uint16_t dest_port = (st->pending_size > st->pending_header_len + ihl + 4) ?
                                 (ip[ihl + 2] << 8) | ip[ihl + 3] : 0;
            uint32_t tsi = get_packet_tsi(ip, st->pending_size - st->pending_header_len);
            printf("\n=== TRACE: DISCARDING INCOMPLETE PACKET ===\n");
            printf("Dest: %d.%d.%d.%d:%d, TSI: %u (0x%x)\n", 
                    ip[16], ip[17], ip[18], ip[19], dest_port, tsi, tsi);
            printf("Started BBP #%u, discarding at BBP #%u (PLP %d)\n", 
                    st->pending_start_bbp, ctx->bbp_count, plp);
            printf("Had %zu of %zu expected bytes (%zu missing, %.1f%% complete)\n",
                    st->pending_size, st->pending_expected, 
                    st->pending_expected - st->pending_size,
                    100.0 * st->pending_size / st->pending_expected);
            printf("First 48 bytes: ");
            for (size_t i = 0; i < 48 && i < st->pending_size; i++) {
                printf("%02x ", st->pending_data[i]);
            }
            printf("\n============================================\n\n");
        } else {
            // Log first 20 discards regardless of type for debugging
            static int general_discard_count = 0;
            if (general_discard_count < 20) {
                general_discard_count++;
                printf("\n=== DISCARD #%d ===\n", general_discard_count);
                printf("Started BBP #%u, discarding at BBP #%u (PLP %d)\n", 
                        st->pending_start_bbp, ctx->bbp_count, plp);
                printf("Had %zu of %zu expected bytes (%zu missing)\n",
                        st->pending_size, st->pending_expected, 
                        st->pending_expected - st->pending_size);
                printf("ALP type=%d\n", pkt_type);
                
                // Show first 48 bytes
                printf("First 48 bytes:\n  ");
                for (size_t i = 0; i < 48 && i < st->pending_size; i++) {
                    printf("%02x ", st->pending_data[i]);
                    if ((i + 1) % 16 == 0) printf("\n  ");
                }
                printf("\n");
                
                // Show last 48 bytes (where the discontinuity happens)
                if (st->pending_size > 48) {
                    size_t start = st->pending_size - 48;
                    printf("Last 48 bytes (offset %zu):\n  ", start);
                    for (size_t i = 0; i < 48; i++) {
                        printf("%02x ", st->pending_data[start + i]);
                        if ((i + 1) % 16 == 0) printf("\n  ");
                    }
                    printf("\n");
                }
                
                // Show what was in current BBP's pre-pointer region
                printf("Current BBP pre-ptr region (%u bytes, ptr=%u):\n  ", pointer, pointer);
                const uint8_t* pre_ptr_data = payload;
                for (size_t i = 0; i < (size_t)pointer && i < 64; i++) {
                    printf("%02x ", pre_ptr_data[i]);
                    if ((i + 1) % 16 == 0) printf("\n  ");
                }
                if (pointer > 64) printf("... (truncated)");
                printf("\n");
                
                // Show start of post-pointer region for context
                printf("Post-ptr start (first 32 bytes):\n  ");
                const uint8_t* post_ptr_data = payload + pointer;
                size_t post_len = payload_len - pointer;
                for (size_t i = 0; i < 32 && i < post_len; i++) {
                    printf("%02x ", post_ptr_data[i]);
                }
                printf("\n");
                
                // Show BBP extension info
                if (bbp_ext_len > 0) {
                    printf("BBP Extension: type=%d len=%u\n", bbp_ext_type, bbp_ext_len);
                    
                    // Check if extension contains non-zero data that might be the missing bytes
                    size_t missing = st->pending_expected - st->pending_size;
                    if (bbp_ext_data && bbp_ext_len >= missing) {
                        // Check last 'missing' bytes of extension for non-zero data
                        size_t check_start = bbp_ext_len - missing;
                        size_t nonzero = 0;
                        for (size_t i = check_start; i < bbp_ext_len; i++) {
                            if (bbp_ext_data[i] != 0x00) nonzero++;
                        }
                        printf("Extension last %zu bytes (where missing data might be): %zu non-zeros\n", 
                                missing, nonzero);
                        if (nonzero > 0) {
                            printf("  Last %zu bytes of extension:\n  ", missing < 64 ? missing : (size_t)64);
                            size_t show_start = bbp_ext_len > 64 ? bbp_ext_len - 64 : 0;
                            for (size_t i = show_start; i < bbp_ext_len && i - show_start < 64; i++) {
                                printf("%02x ", bbp_ext_data[i]);
                                if ((i - show_start + 1) % 16 == 0) printf("\n  ");
                            }
                            printf("\n");
                        }
                    }
                }
                printf("==================\n\n");
            }
            VERBOSE("  BBP #%u Discarding incomplete pending packet (%zu bytes)\n", ctx->bbp_count, st->pending_size);
        }
        st->pending_size = 0;
        st->pending_expected = 0;
    }
    
    // Parse ALP packets from post-pointer region
    size_t pos = 0;
    while (pos < work_len) {
        // Skip stuffing bytes
        while (pos < work_len && work[pos] == 0xFF) pos++;
        if (pos >= work_len) break;
        
        // Debug: dump raw bytes when we first see a type 4 packet
        uint8_t peek_type = (work[pos] >> 5) & 0x07;
        static int raw_type4_dump = 0;
        if (peek_type == 4 && !raw_type4_dump) {
            raw_type4_dump = 1;
            printf("\n=== Raw bytes at type 4 packet start in BBP ===\n");
            printf("Position in work buffer: %zu, work_len: %zu\n", pos, work_len);
            printf("Raw 80 bytes starting at type 4: ");
            for (size_t i = 0; i < 80 && pos + i < work_len; i++) {
                printf("%02x ", work[pos + i]);
                if ((i + 1) % 16 == 0) printf("\n                                   ");
            }
            printf("\n");
            printf("==============================================\n\n");
        }
        
        // Debug: For type 0 packets going to LLS multicast, dump extra context
        // to diagnose length mismatches
        if (peek_type == 0 && work_len - pos >= 24) {
            // Peek at what would be the IP dest address
            // First need to figure out ALP header length
            uint8_t b0 = work[pos];
            uint8_t pc = (b0 >> 4) & 0x01;
            uint8_t hm = (b0 >> 3) & 0x01;
            size_t peek_hlen = 2;
            if (pc == 0 && hm == 1) peek_hlen = 3;
            
            if (pos + peek_hlen + 19 < work_len) {
                const uint8_t* peek_ip = work + pos + peek_hlen;
                // Check for LLS multicast 224.0.23.60
                if (peek_ip[16] == 224 && peek_ip[17] == 0 && peek_ip[18] == 23 && peek_ip[19] == 60) {
                    // This is an LLS packet - dump extensive context
                    static int lls_context_dump = 0;
                    if (lls_context_dump < 5) {
                        lls_context_dump++;
                        uint16_t alp_len = ((b0 & 0x07) << 8) | work[pos + 1];
                        uint16_t ip_len = (peek_ip[2] << 8) | peek_ip[3];
                        
                        printf("\n=== LLS PACKET CONTEXT DUMP #%d (BBP #%u) ===\n", 
                                lls_context_dump, ctx->bbp_count);
                        printf("Position in work buffer: %zu (work_len=%zu)\n", pos, work_len);
                        printf("ALP byte0=0x%02x: type=%d PC=%d HM=%d len_msb=%d\n",
                                b0, peek_type, pc, hm, b0 & 0x07);
                        printf("ALP byte1=0x%02x: len_lsb=%d\n", work[pos+1], work[pos+1]);
                        printf("ALP 11-bit length field: %u (payload bytes)\n", alp_len);
                        printf("ALP header size: %zu, total ALP packet: %zu\n", peek_hlen, peek_hlen + alp_len);
                        printf("IP total_length field: %u\n", ip_len);
                        if (alp_len != ip_len) {
                            printf("*** LENGTH MISMATCH: ALP says %u, IP says %u ***\n", alp_len, ip_len);
                        }
                        printf("\n20 bytes BEFORE this position: ");
                        for (size_t i = (pos >= 20 ? pos - 20 : 0); i < pos; i++) {
                            printf("%02x ", work[i]);
                        }
                        printf("\n60 bytes STARTING at this position: ");
                        for (size_t i = 0; i < 60 && pos + i < work_len; i++) {
                            printf("%02x ", work[pos + i]);
                        }
                        printf("\n==============================================\n\n");
                    }
                }
            }
        }
        
        size_t remaining = work_len - pos;
        if (remaining < 2) {
            // Save as short fragment
            memcpy(st->short_frag, work + pos, remaining);
            st->short_frag_size = remaining;
            break;
        }
        
        size_t hlen, plen;
        size_t total = alp_get_packet_length(work + pos, remaining, &hlen, &plen);
        uint8_t pkt_type = (work[pos] >> 5) & 0x07;
        
        if (total == 0) {
            // Parse error - skip one byte and try to resync
            static int sync_error_count = 0;
            static size_t last_good_pos = 0;
            static size_t last_good_len = 0;
            static uint8_t last_good_type = 0;
            
            if (sync_error_count < 10) {
                sync_error_count++;
                printf("\n=== SYNC ERROR #%d ===\n", sync_error_count);
                printf("Position in work buffer: %zu, work_len: %zu\n", pos, work_len);
                printf("Last good packet: pos=%zu, len=%zu, type=%d\n", 
                        last_good_pos, last_good_len, last_good_type);
                printf("Gap from last good: %zu bytes\n", pos - (last_good_pos + last_good_len));
                printf("Bytes at error: ");
                for (size_t i = 0; i < 16 && pos + i < work_len; i++) {
                    printf("%02x ", work[pos + i]);
                }
                printf("\n");
                // Look for next 45 00 (IP header) to see where we should be
                printf("Searching for '45 00' (IP header): ");
                int found = 0;
                for (size_t i = pos; i < work_len - 1 && i < pos + 32; i++) {
                    if (work[i] == 0x45 && work[i+1] == 0x00) {
                        printf("found at offset +%zu\n", i - pos);
                        found = 1;
                        break;
                    }
                }
                if (!found) printf("not found in next 32 bytes\n");
                printf("====================\n\n");
            }
            ctx->sync_errors++;
            pos++;
            continue;
        }
        
        // Track last good packet for debugging
        static size_t* p_last_good_pos = NULL;
        static size_t* p_last_good_len = NULL; 
        static uint8_t* p_last_good_type = NULL;
        if (!p_last_good_pos) {
            static size_t lgp = 0, lgl = 0;
            static uint8_t lgt = 0;
            p_last_good_pos = &lgp;
            p_last_good_len = &lgl;
            p_last_good_type = &lgt;
        }
        
        if (total > remaining) {
            // Packet extends beyond BBP - save as pending
            // But sanity check - ALP packets shouldn't be huge
            if (total > 65535) {
                VERBOSE("  REJECT: Unreasonable spanning size %zu (type=%d), skipping\n", total, pkt_type);
                ctx->sync_errors++;
                pos++;  // Skip one byte and try to resync
                continue;
            }
            memcpy(st->pending_data, work + pos, remaining);
            st->pending_size = remaining;
            st->pending_expected = total;
            st->pending_header_len = hlen;
            st->pending_start_bbp = ctx->bbp_count;
            st->pending_cont_count = 0;
            ctx->spanning_started++;
            
            // Trace matching packets
            if (pkt_type == 0 && remaining > hlen + 24) {
                const uint8_t* ip_start = work + pos + hlen;
                if (should_trace_packet(ip_start, remaining - hlen)) {
                    uint8_t ihl = (ip_start[0] & 0x0F) * 4;
                    uint16_t dest_port = (ip_start[ihl + 2] << 8) | ip_start[ihl + 3];
                    uint32_t tsi = get_packet_tsi(ip_start, remaining - hlen);
                    printf("\n=== TRACE: SPANNING START (BBP #%u, PLP %d) ===\n", ctx->bbp_count, plp);
                    printf("Dest: %d.%d.%d.%d:%d, TSI: %u (0x%x)\n", 
                            ip_start[16], ip_start[17], ip_start[18], ip_start[19], dest_port, tsi, tsi);
                    printf("Expected total: %zu, have: %zu, need: %zu more\n", 
                            total, remaining, total - remaining);
                    printf("ALP type=%d, hlen=%zu, plen=%zu\n", pkt_type, hlen, plen);
                    printf("First 48 bytes: ");
                    for (size_t i = 0; i < 48 && pos + i < work_len; i++) {
                        printf("%02x ", work[pos + i]);
                    }
                    printf("\n================================================\n\n");
                }
            }
            
            // Debug: dump info for LLS-bound packets (type 0 going to 224.0.23.60)
            if (pkt_type == 0 && remaining >= 22) {
                // Check if dest IP is 224.0.23.60 (LLS multicast)
                const uint8_t* ip_start = work + pos + hlen;
                if (remaining > hlen + 19) {
                    uint8_t dst_ip[4] = {ip_start[16], ip_start[17], ip_start[18], ip_start[19]};
                    if (dst_ip[0] == 224 && dst_ip[1] == 0 && dst_ip[2] == 23 && dst_ip[3] == 60) {
                        printf("\n=== LLS SPANNING PACKET START (BBP #%u) ===\n", ctx->bbp_count);
                        printf("Expected total: %zu, have: %zu, need: %zu more\n", 
                                total, remaining, total - remaining);
                        printf("ALP header (%zu bytes): ", hlen);
                        for (size_t i = 0; i < hlen && pos + i < work_len; i++) {
                            printf("%02x ", work[pos + i]);
                        }
                        printf("\nFirst 32 bytes of IP: ");
                        for (size_t i = 0; i < 32 && pos + hlen + i < work_len; i++) {
                            printf("%02x ", work[pos + hlen + i]);
                        }
                        printf("\n================================================\n\n");
                    }
                }
            }
            
            VERBOSE("  BBP #%u: Spanning packet: have %zu, need %zu (type=%d first_bytes=%02x %02x %02x %02x)\n", 
                    ctx->bbp_count, remaining, total, pkt_type,
                    work[pos], pos+1 < work_len ? work[pos+1] : 0,
                    pos+2 < work_len ? work[pos+2] : 0, pos+3 < work_len ? work[pos+3] : 0);
            break;
        }
        
        // Complete packet - output it
        ctx->pkt_source.plp = plp;
        ctx->pkt_source.bbp_num = ctx->bbp_count;
        ctx->pkt_source.start_bbp = ctx->bbp_count;  // Same as current
        ctx->pkt_source.cont_count = 0;
        ctx->pkt_source.is_spanning = 0;
        ctx->pkt_source.region = "post-ptr";
        
        output_alp_packet(ctx, work + pos, total);
        
        // Debug: if we just output a type 4, show what comes next
        uint8_t just_output_type = (work[pos] >> 5) & 0x07;
        static int showed_post_type4 = 0;
        if (just_output_type == 4 && !showed_post_type4) {
            showed_post_type4 = 1;
            size_t next_pos = pos + total;
            printf("\n=== Bytes following type 4 packet in BBP ===\n");
            printf("Type 4 ended at pos=%zu (len=%zu), work_len=%zu\n", pos, total, work_len);
            printf("Next 32 bytes at pos %zu: ", next_pos);
            for (size_t i = 0; i < 32 && next_pos + i < work_len; i++) {
                printf("%02x ", work[next_pos + i]);
            }
            printf("\n");
            if (next_pos < work_len) {
                uint8_t next_byte = work[next_pos];
                uint8_t next_type = (next_byte >> 5) & 0x07;
                printf("Next byte 0x%02x would be type %d\n", next_byte, next_type);
            }
            printf("=============================================\n\n");
        }
        
        pos += total;
    }
    
    if (free_work) free(work);
}

// ============================================================================
// Process Preamble (L1 Signaling)
// ============================================================================

static void process_preamble(depack_ctx_t* ctx, const uint8_t* data, size_t len) {
    if (len < 2) return;
    
    uint16_t preamble_len = (data[0] << 8) | data[1];
    if (preamble_len > len - 2) return;
    
    ctx->preamble_count++;
    
    // Extract L1-Basic (first 25 bytes after length field)
    if (preamble_len >= STLTP_L1_BASIC_SIZE && ctx->l1_basic_size == 0) {
        memcpy(ctx->l1_basic, data + 2, STLTP_L1_BASIC_SIZE);
        ctx->l1_basic_size = STLTP_L1_BASIC_SIZE;
        
        // Rest is L1-Detail
        size_t detail_len = preamble_len - STLTP_L1_BASIC_SIZE;
        if (detail_len > 0 && detail_len <= ctx->l1_detail_capacity) {
            memcpy(ctx->l1_detail, data + 2 + STLTP_L1_BASIC_SIZE, detail_len);
            ctx->l1_detail_size = detail_len;
        }
        
        DIAG("[L1] Preamble: Basic=%zu Detail=%zu\n", ctx->l1_basic_size, ctx->l1_detail_size);
    }
}

// ============================================================================
// RTP Parsing
// ============================================================================

static int parse_outer_rtp(const uint8_t* data, size_t len,
                           int* marker, uint16_t* pkt_offset,
                           uint16_t* seq_num,
                           const uint8_t** payload, size_t* payload_len) {
    if (len < 12) return -1;
    
    uint8_t ver = (data[0] >> 6) & 0x03;
    uint8_t pad = (data[0] >> 5) & 0x01;
    uint8_t ext = (data[0] >> 4) & 0x01;
    uint8_t cc = data[0] & 0x0F;
    uint8_t m = (data[1] >> 7) & 0x01;
    uint8_t pt = data[1] & 0x7F;
    
    if (ver != 2 || pt != STLTP_OUTER_PT || cc != 0) return -1;
    
    *marker = m;
    *seq_num = (data[2] << 8) | data[3];
    *pkt_offset = (data[10] << 8) | data[11];
    
    size_t hlen = 12;
    if (ext && len >= hlen + 4) {
        uint16_t ext_len = (data[hlen + 2] << 8) | data[hlen + 3];
        hlen += 4 + ext_len * 4;
    }
    
    if (hlen >= len) return -1;
    
    *payload_len = len - hlen;
    if (pad && *payload_len > 0) {
        uint8_t pad_len = data[len - 1];
        if (pad_len <= *payload_len) *payload_len -= pad_len;
    }
    
    *payload = data + hlen;
    return 0;
}

static int parse_inner_rtp(const uint8_t* data, size_t len,
                           uint8_t* pt, int* marker, uint32_t* ssrc,
                           const uint8_t** payload, size_t* payload_len) {
    if (len < 12) return -1;
    
    uint8_t ver = (data[0] >> 6) & 0x03;
    uint8_t pad = (data[0] >> 5) & 0x01;
    uint8_t ext = (data[0] >> 4) & 0x01;
    uint8_t cc = data[0] & 0x0F;
    
    if (ver != 2) return -1;
    
    *marker = (data[1] >> 7) & 0x01;
    *pt = data[1] & 0x7F;
    *ssrc = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    
    size_t hlen = 12 + cc * 4;
    if (ext && len >= hlen + 4) {
        uint16_t ext_len = (data[hlen + 2] << 8) | data[hlen + 3];
        hlen += 4 + ext_len * 4;
    }
    
    if (hlen >= len) return -1;
    
    *payload_len = len - hlen;
    if (pad && *payload_len > 0) {
        uint8_t pad_len = data[len - 1];
        if (pad_len <= *payload_len) *payload_len -= pad_len;
    }
    
    *payload = data + hlen;
    return 0;
}

// ============================================================================
// Route Inner Packet
// ============================================================================

static void route_inner(depack_ctx_t* ctx, uint16_t port, uint8_t pt,
                        int marker, uint32_t ssrc,
                        const uint8_t* data, size_t len) {
    // BBP (ports 30000-30063)
    if (port >= STLTP_PORT_BBP_BASE && port <= STLTP_PORT_BBP_MAX) {
        int plp = port - STLTP_PORT_BBP_BASE;
        if (plp < 0 || plp >= MAX_PLPS) return;
        
        plp_bbp_state_t* bbp = &ctx->bbp[plp];
        
        if (marker) {
            // Flush any previous BBP for THIS PLP
            if (bbp->active && bbp->size >= bbp->expected && bbp->expected > 0) {
                process_bbp(ctx, plp, bbp->buf, bbp->expected);
            }
            
            bbp->expected = ssrc;  // SSRC = BBP length for baseband
            bbp->size = 0;
            bbp->active = true;
        }
        
        if (bbp->active) {
            size_t space = REASSEMBLY_BUFFER_SIZE - bbp->size;
            size_t copy = (len < space) ? len : space;
            memcpy(bbp->buf + bbp->size, data, copy);
            bbp->size += copy;
            
            if (bbp->expected > 0 && bbp->size >= bbp->expected) {
                process_bbp(ctx, plp, bbp->buf, bbp->expected);
                bbp->active = false;
            }
        }
    }
    // Preamble (port 30064)
    else if (port == STLTP_PORT_PREAMBLE && pt == STLTP_PT_PREAMBLE) {
        if (marker) {
            ctx->preamble_size = 0;
            ctx->preamble_active = true;
        }
        
        if (ctx->preamble_active) {
            size_t space = 64 * 1024 - ctx->preamble_size;
            size_t copy = (len < space) ? len : space;
            memcpy(ctx->preamble_buf + ctx->preamble_size, data, copy);
            ctx->preamble_size += copy;
            
            if (ctx->preamble_size >= 2) {
                uint16_t expected = (ctx->preamble_buf[0] << 8) | ctx->preamble_buf[1];
                if (ctx->preamble_size >= (size_t)(expected + 2)) {
                    process_preamble(ctx, ctx->preamble_buf, ctx->preamble_size);
                    ctx->preamble_active = false;
                }
            }
        }
    }
    // T&M (port 30065)
    else if (port == STLTP_PORT_TM && pt == STLTP_PT_TM) {
        if (marker) {
            ctx->tm_size = 0;
            ctx->tm_active = true;
        }
        
        if (ctx->tm_active) {
            size_t space = 64 * 1024 - ctx->tm_size;
            size_t copy = (len < space) ? len : space;
            memcpy(ctx->tm_buf + ctx->tm_size, data, copy);
            ctx->tm_size += copy;
            
            if (ctx->tm_size >= 2) {
                uint16_t expected = (ctx->tm_buf[0] << 8) | ctx->tm_buf[1];
                if (ctx->tm_size >= expected) {
                    ctx->tm_count++;
                    ctx->tm_active = false;
                }
            }
        }
    }
}

// ============================================================================
// Process Tunnel Payload
// ============================================================================

static void process_tunnel(depack_ctx_t* ctx, int outer_marker, uint16_t pkt_offset,
                           const uint8_t* payload, size_t payload_len,
                           uint8_t* cont_buf, size_t* cont_size) {
    // M=0: entire payload is continuation
    if (!outer_marker) {
        if (*cont_size + payload_len < 64 * 1024) {
            memcpy(cont_buf + *cont_size, payload, payload_len);
            *cont_size += payload_len;
        }
        return;
    }
    
    // M=1: handle continuation before pkt_offset
    if (pkt_offset > 0 && *cont_size > 0) {
        size_t cont_bytes = (pkt_offset <= payload_len) ? pkt_offset : payload_len;
        if (*cont_size + cont_bytes < 64 * 1024) {
            memcpy(cont_buf + *cont_size, payload, cont_bytes);
            *cont_size += cont_bytes;
        }
        
        // Try to process completed continuation
        if (*cont_size >= 28 && (cont_buf[0] >> 4) == 4) {
            uint16_t ip_len = (cont_buf[2] << 8) | cont_buf[3];
            if (ip_len <= *cont_size && cont_buf[9] == 17) {
                uint8_t ihl = (cont_buf[0] & 0x0F) * 4;
                if (ihl + 8 <= ip_len) {
                    uint16_t dst_port = (cont_buf[ihl + 2] << 8) | cont_buf[ihl + 3];
                    const uint8_t* inner_rtp = cont_buf + ihl + 8;
                    size_t inner_rtp_len = ip_len - ihl - 8;
                    
                    uint8_t inner_pt;
                    int inner_m;
                    uint32_t inner_ssrc;
                    const uint8_t* inner_payload;
                    size_t inner_payload_len;
                    
                    if (parse_inner_rtp(inner_rtp, inner_rtp_len, &inner_pt, &inner_m,
                                        &inner_ssrc, &inner_payload, &inner_payload_len) == 0) {
                        route_inner(ctx, dst_port, inner_pt, inner_m, inner_ssrc,
                                   inner_payload, inner_payload_len);
                    }
                }
            }
        }
        *cont_size = 0;
    }
    
    // Process packets starting at pkt_offset
    const uint8_t* p = payload + pkt_offset;
    size_t rem = payload_len - pkt_offset;
    
    while (rem >= 20) {
        if ((p[0] >> 4) != 4) break;  // Not IPv4
        
        uint16_t ip_len = (p[2] << 8) | p[3];
        if (ip_len < 20) break;
        
        if (ip_len > rem) {
            // Save for continuation
            if (rem < 64 * 1024) {
                memcpy(cont_buf, p, rem);
                *cont_size = rem;
            }
            break;
        }
        
        if (p[9] == 17) {  // UDP
            uint8_t ihl = (p[0] & 0x0F) * 4;
            if (ihl + 8 <= ip_len) {
                uint16_t dst_port = (p[ihl + 2] << 8) | p[ihl + 3];
                const uint8_t* inner_rtp = p + ihl + 8;
                size_t inner_rtp_len = ip_len - ihl - 8;
                
                uint8_t inner_pt;
                int inner_m;
                uint32_t inner_ssrc;
                const uint8_t* inner_payload;
                size_t inner_payload_len;
                
                if (parse_inner_rtp(inner_rtp, inner_rtp_len, &inner_pt, &inner_m,
                                    &inner_ssrc, &inner_payload, &inner_payload_len) == 0) {
                    route_inner(ctx, dst_port, inner_pt, inner_m, inner_ssrc,
                               inner_payload, inner_payload_len);
                }
            }
        }
        
        p += ip_len;
        rem -= ip_len;
    }
}

// ============================================================================
// Public API
// ============================================================================

const char* get_input_type_string(int input_type) {
    switch(input_type) {
        case INPUT_TYPE_PCAP: return "PCAP File";
        case INPUT_TYPE_DEBUG: return "Debug File";
        case INPUT_TYPE_ALP_PCAP: return "ALP-PCAP File";
        case INPUT_TYPE_STLTP: return "STLTP File";
        default: return "Unknown";
    }
}

int detect_stltp_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return 0;
    
    uint32_t magic;
    if (fread(&magic, 4, 1, f) != 1) { fclose(f); return 0; }
    
    int swapped = (magic == 0xd4c3b2a1);
    if (magic != 0xa1b2c3d4 && !swapped) { fclose(f); return 0; }
    
    fseek(f, 24, SEEK_SET);
    
    int stltp_count = 0;
    for (int i = 0; i < 20; i++) {
        uint32_t ts_sec, ts_usec, incl_len, orig_len;
        if (fread(&ts_sec, 4, 1, f) != 1) break;
        if (fread(&ts_usec, 4, 1, f) != 1) break;
        if (fread(&incl_len, 4, 1, f) != 1) break;
        if (fread(&orig_len, 4, 1, f) != 1) break;
        
        if (swapped) incl_len = __builtin_bswap32(incl_len);
        if (incl_len > 65535 || incl_len < 54) { fseek(f, incl_len, SEEK_CUR); continue; }
        
        uint8_t* pkt = malloc(incl_len);
        if (!pkt || fread(pkt, 1, incl_len, f) != incl_len) { free(pkt); break; }
        
        if ((pkt[12] << 8 | pkt[13]) == 0x0800 && pkt[23] == 17) {
            if ((pkt[42] >> 6) == 2 && (pkt[43] & 0x7F) == STLTP_OUTER_PT) {
                stltp_count++;
            }
        }
        free(pkt);
    }
    
    fclose(f);
    return stltp_count >= 3;
}

int detect_file_type(const char* filename) {
    const char* ext = strrchr(filename, '.');
    if (ext) {
        if (strcasecmp(ext, ".dbg") == 0) return INPUT_TYPE_DEBUG;
        if (strcasecmp(ext, ".pcap") == 0 || strcasecmp(ext, ".pcapng") == 0) {
            if (detect_stltp_file(filename)) return INPUT_TYPE_STLTP;
            
            FILE* f = fopen(filename, "rb");
            if (f) {
                fseek(f, 20, SEEK_SET);
                uint32_t link_type;
                if (fread(&link_type, 4, 1, f) == 1) {
                    if (link_type == DLT_ATSC_ALP || link_type == 289) {
                        fclose(f);
                        return INPUT_TYPE_ALP_PCAP;
                    }
                }
                fclose(f);
            }
            return INPUT_TYPE_PCAP;
        }
    }
    return INPUT_TYPE_PCAP;
}

stltp_extract_t* stltp_extract_create(void) {
    return calloc(1, sizeof(stltp_extract_t));
}

void stltp_extract_free(stltp_extract_t *extract) {
    if (!extract) return;
    free(extract->alp_data);
    free(extract->l1_basic);
    free(extract->l1_detail);
    free(extract->l1_basic_b64);
    free(extract->l1_detail_b64);
    free(extract->timing_mgmt);
    free(extract);
}

int process_stltp_file(const char *filename, stltp_extract_t *extract) {
    printf("STLTP input.c version: 2025-01-20-v13 (DUMP_BBP_START/END support)\n");
    fflush(stdout);
    
    const char* verbose_env = getenv("STLTP_VERBOSE");
    g_verbose = (verbose_env && verbose_env[0] == '1');
    
    const char* diag_env = getenv("STLTP_DIAG");
    if (diag_env && diag_env[0]) {
        g_diag = 1;
        g_diag_out = (diag_env[0] != '1' || diag_env[1]) ? fopen(diag_env, "w") : stderr;
        if (!g_diag_out) g_diag_out = stderr;
    }
    
    init_trace_config();
    
    FILE *f = fopen(filename, "rb");
    if (!f) { printf("Cannot open %s\n", filename); return 1; }
    
    uint32_t magic;
    if (fread(&magic, 4, 1, f) != 1) { fclose(f); return 1; }
    
    int swapped = (magic == 0xd4c3b2a1);
    if (magic != 0xa1b2c3d4 && !swapped) { fclose(f); return 1; }
    
    fseek(f, 24, SEEK_SET);
    
    depack_ctx_t* ctx = depack_new();
    if (!ctx) { fclose(f); return 1; }
    
    uint8_t* cont_buf = malloc(64 * 1024);
    size_t cont_size = 0;
    
    printf("Processing: %s\n", filename);
    
    while (1) {
        uint32_t ts_sec, ts_usec, incl_len, orig_len;
        if (fread(&ts_sec, 4, 1, f) != 1) break;
        if (fread(&ts_usec, 4, 1, f) != 1) break;
        if (fread(&incl_len, 4, 1, f) != 1) break;
        if (fread(&orig_len, 4, 1, f) != 1) break;
        
        if (swapped) incl_len = __builtin_bswap32(incl_len);
        if (incl_len > 65535) { fseek(f, incl_len, SEEK_CUR); continue; }
        
        uint8_t* pkt = malloc(incl_len);
        if (!pkt || fread(pkt, 1, incl_len, f) != incl_len) { free(pkt); break; }
        
        if (incl_len < 54 || (pkt[12] << 8 | pkt[13]) != 0x0800 || pkt[23] != 17) {
            free(pkt); continue;
        }
        
        int outer_m;
        uint16_t pkt_offset;
        uint16_t seq_num;
        const uint8_t* outer_payload;
        size_t outer_payload_len;
        
        if (parse_outer_rtp(pkt + 42, incl_len - 42, &outer_m, &pkt_offset,
                           &seq_num, &outer_payload, &outer_payload_len) == 0) {
            // Check for sequence number gaps
            if (ctx->outer_seq_valid) {
                uint16_t expected = ctx->last_outer_seq + 1;
                if (seq_num != expected) {
                    // Gap detected - calculate how many packets were lost
                    uint16_t gap = (seq_num > expected) ? (seq_num - expected) : (65536 - expected + seq_num);
                    ctx->outer_seq_gaps++;
                    ctx->outer_seq_gap_packets += gap;
                    
                    // Log first 10 gaps
                    static int gap_log_count = 0;
                    if (gap_log_count < 10) {
                        gap_log_count++;
                        printf("\n=== RTP SEQUENCE GAP #%d (BBP #%u) ===\n", gap_log_count, ctx->bbp_count);
                        printf("Expected seq %u, got %u (%u packets lost)\n", expected, seq_num, gap);
                        printf("=====================================\n\n");
                    }
                }
            }
            ctx->last_outer_seq = seq_num;
            ctx->outer_seq_valid = 1;
            
            ctx->outer_pkts++;
            process_tunnel(ctx, outer_m, pkt_offset, outer_payload, outer_payload_len,
                          cont_buf, &cont_size);
        }
        
        free(pkt);
    }
    
    fclose(f);
    free(cont_buf);
    
    // Copy results
    if (ctx->out_alp_size > 0) {
        extract->alp_data = malloc(ctx->out_alp_size);
        if (extract->alp_data) {
            memcpy(extract->alp_data, ctx->out_alp, ctx->out_alp_size);
            extract->alp_size = ctx->out_alp_size;
        }
    }
    
    if (ctx->l1_basic_size > 0) {
        extract->l1_basic = malloc(ctx->l1_basic_size);
        if (extract->l1_basic) {
            memcpy(extract->l1_basic, ctx->l1_basic, ctx->l1_basic_size);
            extract->l1_basic_size = ctx->l1_basic_size;
        }
        
        size_t b64_len;
        extract->l1_basic_b64 = base64_encode(ctx->l1_basic, ctx->l1_basic_size, &b64_len);
        
        if (ctx->l1_detail_size > 0) {
            extract->l1_detail = malloc(ctx->l1_detail_size);
            if (extract->l1_detail) {
                memcpy(extract->l1_detail, ctx->l1_detail, ctx->l1_detail_size);
                extract->l1_detail_size = ctx->l1_detail_size;
            }
            
            size_t combined_size = ctx->l1_basic_size + ctx->l1_detail_size;
            uint8_t* combined = malloc(combined_size);
            if (combined) {
                memcpy(combined, ctx->l1_basic, ctx->l1_basic_size);
                memcpy(combined + ctx->l1_basic_size, ctx->l1_detail, ctx->l1_detail_size);
                extract->l1_detail_b64 = base64_encode(combined, combined_size, &b64_len);
                free(combined);
            }
        }
    }
    
    extract->rtp_packet_count = ctx->outer_pkts;
    extract->alp_packet_count = ctx->out_alp_count;
    extract->preamble_packet_count = ctx->preamble_count;
    extract->timing_packet_count = ctx->tm_count;
    
    printf("\nSTLTP Processing Complete:\n");
    printf("  Outer packets:    %u\n", ctx->outer_pkts);
    printf("  BBPs processed:   %u\n", ctx->bbp_count);
    printf("  Preambles:        %u\n", ctx->preamble_count);
    printf("  T&M packets:      %u\n", ctx->tm_count);
    printf("  ALP packets:      %u\n", ctx->out_alp_count);
    printf("    Type 0 (IPv4):      %u\n", ctx->alp_type_counts[0]);
    printf("    Type 2 (Compressed):%u\n", ctx->alp_type_counts[2]);
    printf("    Type 4 (Signaling): %u\n", ctx->alp_type_counts[4]);
    printf("    Type 6 (Extension): %u\n", ctx->alp_type_counts[6]);
    printf("    Type 7 (MPEG-TS):   %u\n", ctx->alp_type_counts[7]);
    printf("  Spanning packets:\n");
    printf("    Started:        %u\n", ctx->spanning_started);
    printf("    Completed:      %u\n", ctx->spanning_complete);
    printf("    Discarded:      %u\n", ctx->spanning_discarded);
    printf("    Orphan conts:   %u\n", ctx->orphan_continuations);
    printf("  Rejected packets: %u\n", ctx->rejected_packets);
    printf("  Sync errors:      %u\n", ctx->sync_errors);
    if (ctx->outer_seq_gaps > 0) {
        printf("  RTP seq gaps:     %u (est. %u packets lost)\n", 
               ctx->outer_seq_gaps, ctx->outer_seq_gap_packets);
    }
    printf("  Total ALP bytes:  %zu\n", ctx->out_alp_size);
    
    // Print trace stats if tracing was enabled
    if (g_trace_dest_ip != 0 || g_trace_dest_port != 0 || g_trace_tsi_set) {
        printf("\nTrace Statistics:\n");
        printf("  Packets checked:  %u\n", g_trace_checked);
        printf("  Packets matched:  %u\n", g_trace_matched);
        printf("  Unique TSIs seen: %d\n", g_seen_tsi_count);
    }
    
    depack_free(ctx);
    return 0;
}

int create_virtual_alp_pcap_from_stltp(const char *stltp_filename,
                                        uint8_t **pcap_data, size_t *pcap_size,
                                        char **l1_basic_b64, char **l1_detail_b64) {
    *pcap_data = NULL;
    *pcap_size = 0;
    if (l1_basic_b64) *l1_basic_b64 = NULL;
    if (l1_detail_b64) *l1_detail_b64 = NULL;
    
    stltp_extract_t* extract = stltp_extract_create();
    if (!extract) return 1;
    
    if (process_stltp_file(stltp_filename, extract) != 0) {
        stltp_extract_free(extract);
        return 1;
    }
    
    if (extract->alp_size == 0) {
        printf("Warning: No ALP data extracted\n");
        stltp_extract_free(extract);
        return 1;
    }
    
    // Create PCAP from extracted ALP packets
    // Each ALP packet in extract->alp_data is properly delimited
    size_t est_size = 24 + extract->alp_packet_count * (16 + 2000);
    *pcap_data = malloc(est_size);
    if (!*pcap_data) { stltp_extract_free(extract); return 1; }
    
    size_t pos = 0;
    
    // PCAP header
    struct {
        uint32_t magic, v_major_minor;
        int32_t thiszone;
        uint32_t sigfigs, snaplen, network;
    } pcap_hdr = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, DLT_ATSC_ALP};
    memcpy(*pcap_data, &pcap_hdr, 24);
    pos = 24;
    
    uint32_t ts = (uint32_t)time(NULL);
    size_t alp_pos = 0;
    uint32_t pkt_num = 0;
    
    while (alp_pos < extract->alp_size) {
        const uint8_t* pkt = extract->alp_data + alp_pos;
        size_t rem = extract->alp_size - alp_pos;
        
        if (rem < 2) break;
        
        size_t hlen, plen;
        size_t pkt_len = alp_get_packet_length(pkt, rem, &hlen, &plen);
        
        if (pkt_len == 0 || pkt_len > rem) {
            alp_pos++;
            continue;
        }
        
        // Debug: track packet types being written
        uint8_t pkt_type = (pkt[0] >> 5) & 0x07;
        static int type4_context_dumped = 0;
        if (pkt_type == 4 && !type4_context_dumped) {
            type4_context_dumped = 1;
            printf("\n=== Context around first type 4 packet ===\n");
            printf("Position in ALP buffer: %zu\n", alp_pos);
            printf("PCAP position: %zu (packet #%u)\n", pos, pkt_num);
            
            // Show previous packet info
            if (pkt_num > 0) {
                // Look back in PCAP buffer to find previous packet
                size_t prev_pos = 24;  // Start after PCAP header
                size_t last_pkt_start = 24;
                uint32_t last_pkt_len = 0;
                
                while (prev_pos < pos) {
                    uint32_t incl_len;
                    memcpy(&incl_len, *pcap_data + prev_pos + 8, 4);
                    last_pkt_start = prev_pos + 16;  // Data starts after record header
                    last_pkt_len = incl_len;
                    prev_pos += 16 + incl_len;
                }
                
                if (last_pkt_len > 0) {
                    const uint8_t* prev_pkt = *pcap_data + last_pkt_start;
                    uint8_t prev_type = (prev_pkt[0] >> 5) & 0x07;
                    printf("Previous packet: type=%d, len=%u\n", prev_type, last_pkt_len);
                    printf("  Last 32 bytes: ");
                    size_t start = (last_pkt_len > 32) ? last_pkt_len - 32 : 0;
                    for (size_t i = start; i < last_pkt_len; i++) {
                        printf("%02x ", prev_pkt[i]);
                    }
                    printf("\n");
                }
            }
            
            printf("Type 4 packet: len=%zu\n", pkt_len);
            printf("  First 64 bytes: ");
            for (size_t i = 0; i < pkt_len && i < 64; i++) {
                printf("%02x ", pkt[i]);
                if ((i + 1) % 16 == 0) printf("\n                  ");
            }
            printf("\n");
            
            // Also show what comes after
            if (alp_pos + pkt_len < extract->alp_size) {
                const uint8_t* next_pkt = extract->alp_data + alp_pos + pkt_len;
                size_t next_rem = extract->alp_size - alp_pos - pkt_len;
                if (next_rem >= 2) {
                    size_t next_hlen, next_plen;
                    size_t next_len = alp_get_packet_length(next_pkt, next_rem, &next_hlen, &next_plen);
                    uint8_t next_type = (next_pkt[0] >> 5) & 0x07;
                    printf("Next packet: type=%d, len=%zu\n", next_type, next_len);
                    printf("  First 20 bytes: ");
                    for (size_t i = 0; i < 20 && i < next_rem; i++) {
                        printf("%02x ", next_pkt[i]);
                    }
                    printf("\n");
                }
            }
            printf("===========================================\n\n");
        }
        
        // Grow buffer if needed
        if (pos + 16 + pkt_len > est_size) {
            est_size *= 2;
            uint8_t* new_buf = realloc(*pcap_data, est_size);
            if (!new_buf) break;
            *pcap_data = new_buf;
        }
        
        // Write record
        struct { uint32_t ts_sec, ts_usec, incl_len, orig_len; } rec = {
            ts + pkt_num / 1000, (pkt_num % 1000) * 1000, (uint32_t)pkt_len, (uint32_t)pkt_len
        };
        memcpy(*pcap_data + pos, &rec, 16);
        pos += 16;
        memcpy(*pcap_data + pos, pkt, pkt_len);
        pos += pkt_len;
        
        alp_pos += pkt_len;
        pkt_num++;
    }
    
    // Debug: Write first 5000 packets to a debug PCAP file
    {
        FILE* dbg = fopen("/tmp/stltp_debug.pcap", "wb");
        if (dbg) {
            // Write up to first 5000 packets or entire file, whichever is smaller
            size_t dbg_pos = 24;  // Start after PCAP header
            uint32_t dbg_count = 0;
            
            fwrite(*pcap_data, 1, 24, dbg);  // PCAP header
            
            while (dbg_pos < pos && dbg_count < 5000) {
                // Read record header
                uint32_t incl_len;
                memcpy(&incl_len, *pcap_data + dbg_pos + 8, 4);
                
                size_t rec_size = 16 + incl_len;
                if (dbg_pos + rec_size > pos) break;
                
                fwrite(*pcap_data + dbg_pos, 1, rec_size, dbg);
                dbg_pos += rec_size;
                dbg_count++;
            }
            
            fclose(dbg);
            printf("DEBUG: Wrote %u packets to /tmp/stltp_debug.pcap\n", dbg_count);
        }
    }
    
    *pcap_size = pos;
    
    if (l1_basic_b64 && extract->l1_basic_b64) {
        *l1_basic_b64 = extract->l1_basic_b64;
        extract->l1_basic_b64 = NULL;
    }
    if (l1_detail_b64 && extract->l1_detail_b64) {
        *l1_detail_b64 = extract->l1_detail_b64;
        extract->l1_detail_b64 = NULL;
    }
    
    printf("Created ALP-PCAP: %zu bytes, %u packets\n", *pcap_size, pkt_num);
    
    stltp_extract_free(extract);
    return 0;
}

// ============================================================================
// parse_alp_packet - Used by downstream processing
// ============================================================================

int parse_alp_packet(const u_char* alp_data, int alp_len,
                     const u_char** ip_payload, int* ip_len,
                     const u_char** signaling_payload, int* signaling_len) {
    *ip_payload = NULL;
    *ip_len = 0;
    *signaling_payload = NULL;
    *signaling_len = 0;
    
    if (alp_len < 2) return ALP_PARSE_ERROR;
    
    uint8_t b0 = alp_data[0];
    uint8_t type = (b0 >> 5) & 0x07;
    uint8_t pc = (b0 >> 4) & 0x01;
    uint8_t hm = (b0 >> 3) & 0x01;
    
    // Get header and payload lengths
    size_t hlen, plen;
    size_t total = alp_get_packet_length(alp_data, alp_len, &hlen, &plen);
    
    if (total == 0 || total > (size_t)alp_len) {
        return ALP_PARSE_ERROR;
    }
    
    if (type == 0) {
        // IPv4 packet
        const uint8_t* ip = alp_data + hlen;
        size_t ip_avail = alp_len - hlen;
        
        if (ip_avail < 20) return ALP_PARSE_ERROR;
        if ((ip[0] >> 4) != 4) return ALP_PARSE_ERROR;  // Not IPv4
        
        uint16_t ip_total = (ip[2] << 8) | ip[3];
        if (ip_total > ip_avail) return ALP_PARSE_ERROR;
        
        *ip_payload = ip;
        *ip_len = ip_total;
        return ALP_PARSE_IPV4;
    }
    else if (type == 4) {
        // Signaling packet (LLS)
        // Per A/330 Section 5.2.1, signaling packets have a 5-byte info header:
        //   signaling_type (1 byte)
        //   signaling_type_extension (2 bytes)
        //   signaling_version (1 byte)
        //   signaling_format/encoding/reserved (1 byte)
        // After this header comes the actual LLS table data
        // Note: We return the full payload INCLUDING the 5-byte header
        // because the downstream LMT parser expects to skip it itself
        // 
        // hlen is 7 (2 ALP + 5 signaling info), but we want to return
        // data starting at the signaling info header (offset 2)
        
        *signaling_payload = alp_data + 2;  // Skip only ALP header, keep signaling info
        *signaling_len = plen + 5;          // Include signaling info header in length
        return ALP_PARSE_SIGNALING;
    }
    else if (type == 6) {
        // Extension packet
        *signaling_payload = alp_data + hlen;
        *signaling_len = plen;
        return ALP_PARSE_EXTENSION_ONLY;
    }
    
    return ALP_PARSE_ERROR;
}

// ============================================================================
// Utility functions
// ============================================================================

void multicast_ip_to_mac(uint32_t ip, uint8_t *mac) {
    mac[0] = 0x01; mac[1] = 0x00; mac[2] = 0x5e;
    mac[3] = (ip >> 16) & 0x7f;
    mac[4] = (ip >> 8) & 0xff;
    mac[5] = ip & 0xff;
}

uint8_t* remove_variable_artifacts(const uint8_t *data, size_t data_len, size_t *cleaned_len) {
    uint8_t *cleaned_data = malloc(data_len);
    if (!cleaned_data) {
        printf("Memory allocation failed\n");
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
                    artifact_len = 3;
                    three_byte_count++;
                } else if (flag_nibble == 0x4) {
                    artifact_len = 4;
                    four_byte_count++;
                } else {
                    artifact_len = 3;
                    three_byte_count++;
                }
                
                pos += artifact_len;
                removed_count++;
                
                int remaining_in_chunk = 188 - artifact_len;
                if (pos + remaining_in_chunk <= data_len) {
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining_in_chunk);
                    cleaned_pos += remaining_in_chunk;
                    pos += remaining_in_chunk;
                } else {
                    size_t remaining = data_len - pos;
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                    cleaned_pos += remaining;
                    break;
                }
            } else {
                memcpy(cleaned_data + cleaned_pos, data + pos, 188);
                cleaned_pos += 188;
                pos += 188;
            }
        } else {
            size_t remaining = data_len - pos;
            if (remaining >= 2 && data[pos] == 0xe7) {
                uint8_t second_byte = data[pos + 1];
                uint8_t flag_nibble = second_byte >> 4;
                int artifact_len = (flag_nibble == 0x4) ? 4 : 3;
                
                if (remaining >= (size_t)artifact_len) {
                    pos += artifact_len;
                    removed_count++;
                    
                    if (pos < data_len) {
                        size_t final_remaining = data_len - pos;
                        memcpy(cleaned_data + cleaned_pos, data + pos, final_remaining);
                        cleaned_pos += final_remaining;
                    }
                } else {
                    memcpy(cleaned_data + cleaned_pos, data + pos, remaining);
                    cleaned_pos += remaining;
                }
            } else {
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

int create_virtual_pcap_from_debug(const char *debug_filename, uint8_t **pcap_data, size_t *pcap_size) {
    FILE *input_file = fopen(debug_filename, "rb");
    if (!input_file) {
        printf("Error: Cannot open debug file %s\n", debug_filename);
        return 1;
    }
    
    fseek(input_file, 0, SEEK_END);
    size_t file_size = ftell(input_file);
    fseek(input_file, 0, SEEK_SET);
    
    printf("Debug file size: %zu bytes\n", file_size);
    
    uint8_t *raw_data = malloc(file_size);
    if (!raw_data) {
        printf("Memory allocation failed\n");
        fclose(input_file);
        return 1;
    }
    
    size_t bytes_read = fread(raw_data, 1, file_size, input_file);
    fclose(input_file);
    
    if (bytes_read != file_size) {
        printf("Error reading debug file\n");
        free(raw_data);
        return 1;
    }
    
    size_t cleaned_len;
    uint8_t *cleaned_data = remove_variable_artifacts(raw_data, file_size, &cleaned_len);
    free(raw_data);
    
    if (!cleaned_data) {
        return 1;
    }
    
    printf("Cleaned data size: %zu bytes\n", cleaned_len);
    printf("Scanning for IPv4 multicast UDP packets...\n");
    
    // Allocate array for packet offsets - use a reasonable upper bound
    size_t max_packets = cleaned_len / 20;
    if (max_packets == 0) max_packets = 1;
    size_t *packet_offsets = malloc(max_packets * sizeof(size_t));
    if (!packet_offsets) {
        printf("Memory allocation failed for packet_offsets\n");
        free(cleaned_data);
        return 1;
    }
    size_t packet_count = 0;
    
    for (size_t pos = 0; pos + 20 <= cleaned_len; pos++) {
        if (cleaned_data[pos] == 0x45 &&
            cleaned_data[pos + 9] == 17 &&
            cleaned_data[pos + 16] >= 224 &&
            cleaned_data[pos + 16] <= 239) {
            
            uint8_t version = cleaned_data[pos] >> 4;
            uint8_t ihl = cleaned_data[pos] & 0xF;
            
            if (version == 4 && ihl >= 5) {
                if (packet_count < max_packets) {
                    packet_offsets[packet_count++] = pos;
                }
            }
        }
    }
    
    printf("Found %zu potential packets in debug file\n", packet_count);
    
    // Calculate estimated size more carefully
    size_t estimated_size = 24;  // PCAP header
    for (size_t i = 0; i < packet_count; i++) {
        size_t current_start = packet_offsets[i];
        if (current_start + 4 <= cleaned_len) {
            uint16_t total_len = (cleaned_data[current_start + 2] << 8) | cleaned_data[current_start + 3];
            if (total_len >= 20) {
                estimated_size += 16 + 14 + total_len;  // record header + eth header + IP packet
            }
        }
    }
    
    *pcap_data = malloc(estimated_size);
    if (!*pcap_data) {
        printf("Memory allocation failed for pcap_data\n");
        free(cleaned_data);
        free(packet_offsets);
        return 1;
    }
    
    size_t pcap_pos = 0;
    
    // PCAP global header
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
    size_t packets_written = 0;
    
    for (size_t i = 0; i < packet_count; i++) {
        size_t current_start = packet_offsets[i];
        size_t next_start = (i + 1 < packet_count) ? packet_offsets[i + 1] : cleaned_len;
        size_t packet_chunk_len = next_start - current_start;
        
        if (packet_chunk_len < 20) continue;
        if (current_start + 4 > cleaned_len) continue;
        
        uint16_t total_len = (cleaned_data[current_start + 2] << 8) | cleaned_data[current_start + 3];
        
        // Validate the packet
        if (total_len >= 20 && total_len <= packet_chunk_len && 
            current_start + total_len <= cleaned_len) {
            
            uint32_t dest_ip = (cleaned_data[current_start + 16] << 24) |
                              (cleaned_data[current_start + 17] << 16) |
                              (cleaned_data[current_start + 18] << 8) |
                              cleaned_data[current_start + 19];
            
            uint8_t eth_header[14];
            multicast_ip_to_mac(dest_ip, eth_header);
            
            eth_header[6] = 0x00;
            eth_header[7] = 0x11;
            eth_header[8] = 0x22;
            eth_header[9] = 0x33;
            eth_header[10] = 0x44;
            eth_header[11] = 0x55;
            eth_header[12] = 0x08;
            eth_header[13] = 0x00;
            
            uint32_t full_packet_len = 14 + total_len;
            
            // Make sure we don't overflow
            if (pcap_pos + 16 + full_packet_len > estimated_size) {
                printf("Warning: PCAP buffer overflow prevented, stopping\n");
                break;
            }
            
            struct {
                uint32_t ts_sec;
                uint32_t ts_usec;
                uint32_t incl_len;
                uint32_t orig_len;
            } rec_hdr = {
                .ts_sec = timestamp + (uint32_t)i,
                .ts_usec = 0,
                .incl_len = full_packet_len,
                .orig_len = full_packet_len
            };
            
            memcpy(*pcap_data + pcap_pos, &rec_hdr, 16);
            pcap_pos += 16;
            
            memcpy(*pcap_data + pcap_pos, eth_header, 14);
            pcap_pos += 14;
            memcpy(*pcap_data + pcap_pos, cleaned_data + current_start, total_len);
            pcap_pos += total_len;
            packets_written++;
        }
    }
    
    *pcap_size = pcap_pos;
    
    free(cleaned_data);
    free(packet_offsets);
    
    printf("Created virtual PCAP with %zu packets (%zu bytes)\n", packets_written, *pcap_size);
    return 0;
}
