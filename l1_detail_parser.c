/*
 * l1_detail_parser.c
 *
 * ATSC 3.0 L1 Detail and PLP Information Parser Implementation
 * Abstracted from hdhomerun_tui.c for reuse in other applications
 *
 * HDHomeRun TUI - Copyright (C) 2025 - Mark J. Colombo
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "l1_detail_parser.h"
#include "hdhomerun.h"
#include "hdhomerun_device.h"

// ATSC 3.0 SNR Lookup Table
static const struct modcod_snr_complete {
    char mod[16];
    char cod[8];
    float awgn_long;
    float rayleigh_long;
    float awgn_short;
    float rayleigh_short;
} snr_table_complete[] = {
    // QPSK
    {"QPSK", "2/15", -6.23, -5.72, -5.55, -5.06}, {"QPSK", "3/15", -4.32, -3.62, -3.73, -2.97},
    {"QPSK", "4/15", -2.89, -1.97, -2.32, -1.36}, {"QPSK", "5/15", -1.70, -0.55, -1.30, -0.08},
    {"QPSK", "6/15", -0.54, 0.86, -0.33, 1.15}, {"QPSK", "7/15", 0.30, 1.95, 0.56, 2.30},
    {"QPSK", "8/15", 1.16, 3.16, 1.38, 3.44}, {"QPSK", "9/15", 1.97, 4.35, 2.20, 4.70},
    {"QPSK", "10/15", 2.77, 5.62, 2.94, 5.97}, {"QPSK", "11/15", 3.60, 7.05, 3.82, 7.46},
    {"QPSK", "12/15", 4.49, 8.76, 4.70, 9.15}, {"QPSK", "13/15", 5.53, 10.97, 5.76, 11.56},
    
    // 16QAM
    {"16QAM", "2/15", -2.73, -1.84, -2.15, -1.14}, {"16QAM", "3/15", -0.25, 0.81, 0.35, 1.45},
    {"16QAM", "4/15", 1.46, 2.69, 1.99, 3.41}, {"16QAM", "5/15", 2.82, 4.32, 3.16, 4.78},
    {"16QAM", "6/15", 4.21, 5.98, 4.45, 6.27}, {"16QAM", "7/15", 5.21, 7.21, 5.51, 7.58},
    {"16QAM", "8/15", 6.30, 8.63, 6.51, 8.96}, {"16QAM", "9/15", 7.32, 9.94, 7.58, 10.28},
    {"16QAM", "10/15", 8.36, 11.40, 8.59, 11.73}, {"16QAM", "11/15", 9.50, 12.78, 9.74, 13.22},
    {"16QAM", "12/15", 10.57, 14.60, 10.81, 14.97}, {"16QAM", "13/15", 11.83, 16.85, 12.09, 17.44},
    
    // 64QAM
    {"64QAM", "2/15", -0.26, 0.86, 0.35, 1.60}, {"64QAM", "3/15", 2.27, 3.61, 2.85, 4.30},
    {"64QAM", "4/15", 4.15, 5.88, 4.65, 6.55}, {"64QAM", "5/15", 5.96, 7.74, 6.30, 8.29},
    {"64QAM", "6/15", 7.66, 9.72, 7.93, 10.05}, {"64QAM", "7/15", 8.92, 11.10, 9.29, 11.54},
    {"64QAM", "8/15", 10.31, 12.75, 10.56, 13.09}, {"64QAM", "9/15", 11.55, 14.25, 11.83, 14.62},
    {"64QAM", "10/15", 12.88, 15.81, 13.13, 16.20}, {"64QAM", "11/15", 14.28, 17.44, 14.52, 17.87},
    {"64QAM", "12/15", 15.57, 19.39, 15.86, 19.82}, {"64QAM", "13/15", 17.03, 21.82, 17.33, 22.44},
    
    // 256QAM
    {"256QAM", "2/15", 1.60, 2.89, 2.27, 3.60}, {"256QAM", "3/15", 4.30, 5.97, 4.78, 6.79},
    {"256QAM", "4/15", 6.57, 8.46, 7.19, 9.32}, {"256QAM", "5/15", 8.53, 10.59, 8.93, 11.16},
    {"256QAM", "6/15", 10.61, 12.92, 10.91, 13.29}, {"256QAM", "7/15", 12.10, 14.58, 12.57, 15.15},
    {"256QAM", "8/15", 13.91, 16.54, 14.25, 16.95}, {"256QAM", "9/15", 15.55, 18.23, 15.80, 18.64},
    {"256QAM", "10/15", 17.13, 20.06, 17.45, 20.50}, {"256QAM", "11/15", 18.76, 21.94, 19.08, 22.40},
    {"256QAM", "12/15", 20.44, 24.01, 20.78, 24.54}, {"256QAM", "13/15", 22.22, 26.62, 22.55, 27.23},
    
    // 1024QAM
    {"1024QAM", "2/15", 3.23, 4.65, 0.0, 0.0}, {"1024QAM", "3/15", 6.17, 8.04, 0.0, 0.0},
    {"1024QAM", "4/15", 8.77, 10.85, 0.0, 0.0}, {"1024QAM", "5/15", 11.07, 13.25, 0.0, 0.0},
    {"1024QAM", "6/15", 13.46, 15.91, 0.0, 0.0}, {"1024QAM", "7/15", 15.30, 17.84, 0.0, 0.0},
    {"1024QAM", "8/15", 17.46, 20.13, 0.0, 0.0}, {"1024QAM", "9/15", 19.45, 22.34, 0.0, 0.0},
    {"1024QAM", "10/15", 21.35, 24.47, 0.0, 0.0}, {"1024QAM", "11/15", 23.43, 26.61, 0.0, 0.0},
    {"1024QAM", "12/15", 25.52, 28.82, 0.0, 0.0}, {"1024QAM", "13/15", 27.62, 31.59, 0.0, 0.0},
    
    // 4096QAM
    {"4096QAM", "2/15", 4.58, 6.23, 0.0, 0.0}, {"4096QAM", "3/15", 7.85, 9.83, 0.0, 0.0},
    {"4096QAM", "4/15", 10.73, 12.95, 0.0, 0.0}, {"4096QAM", "5/15", 13.45, 15.75, 0.0, 0.0},
    {"4096QAM", "6/15", 16.04, 18.79, 0.0, 0.0}, {"4096QAM", "7/15", 18.22, 21.03, 0.0, 0.0},
    {"4096QAM", "8/15", 20.69, 23.67, 0.0, 0.0}, {"4096QAM", "9/15", 23.05, 26.37, 0.0, 0.0},
    {"4096QAM", "10/15", 25.55, 28.64, 0.0, 0.0}, {"4096QAM", "11/15", 28.11, 31.18, 0.0, 0.0},
    {"4096QAM", "12/15", 30.34, 33.82, 0.0, 0.0}, {"4096QAM", "13/15", 32.83, 36.54, 0.0, 0.0},
    
    {{0}} // Sentinel
};

// Base64 decoding tables
static int b64invs[] = { 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58,
    59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
    21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
    43, 44, 45, 46, 47, 48, 49, 50, 51 };

// Global variables for bit parser
#define L1_DUMP_BUFFER_SIZE 512
static char bits[L1_DUMP_BUFFER_SIZE * 8];
static int bits_index = 0;

// Helper to add a line to the display buffer safely
#define add_line(info, ...) \
    if ((info)->line_count < (info)->max_lines) { \
        char line_buf[512]; \
        snprintf(line_buf, sizeof(line_buf), __VA_ARGS__); \
        (info)->display_lines[(info)->line_count++] = strdup(line_buf); \
    }

// Function implementations
struct l1_detail_info* create_l1_detail_info(int max_lines) {
    struct l1_detail_info* info = malloc(sizeof(struct l1_detail_info));
    if (!info) return NULL;
    
    info->display_lines = malloc(max_lines * sizeof(char*));
    if (!info->display_lines) {
        free(info);
        return NULL;
    }
    
    info->line_count = 0;
    info->max_lines = max_lines;
    info->context.ldpc_info_available = false;
    info->context.ldpc_length = -1;
    
    return info;
}

void free_l1_detail_info(struct l1_detail_info* info) {
    if (!info) return;
    
    for (int i = 0; i < info->line_count; i++) {
        free(info->display_lines[i]);
    }
    free(info->display_lines);
    free(info);
}

long parse_status_value_l1(const char *status_str, const char *key) {
    const char *found = strstr(status_str, key);
    if (found) {
        return strtol(found + strlen(key), NULL, 0);
    }
    return -999;
}

void normalize_mod_str_l1(const char *in, char *out, size_t out_size) {
    char digits[8] = {0};
    char alphas[8] = {0};
    int d_idx = 0;
    int a_idx = 0;

    for (int i = 0; in[i] != '\0' && i < 15; i++) {
        if (isdigit((unsigned char)in[i])) {
            if (d_idx < 7) digits[d_idx++] = in[i];
        } else {
            if (a_idx < 7) alphas[a_idx++] = toupper((unsigned char)in[i]);
        }
    }
    
    if (d_idx > 0) {
        snprintf(out, out_size, "%s%s", digits, alphas);
    } else {
        snprintf(out, out_size, "%s", alphas);
    }
}

struct snr_pair_result get_snr_pair_for_modcod_l1(const char* mod, const char* cod, int ldpc_length) {
    struct snr_pair_result result = {false, false, 0.0, 0.0, 0.0, 0.0, ""};
    
    const struct modcod_snr_complete* entry = NULL;
    for (int i = 0; snr_table_complete[i].mod[0] != 0; i++) {
        if (strcmp(snr_table_complete[i].mod, mod) == 0 && strcmp(snr_table_complete[i].cod, cod) == 0) {
            entry = &snr_table_complete[i];
            break;
        }
    }
    
    if (!entry) return result;
    
    result.found = true;
    
    if (ldpc_length == 0) {
        if (entry->awgn_short != 0.0 && entry->rayleigh_short != 0.0) {
            result.ldpc_length_known = true;
            result.awgn_min = result.awgn_max = entry->awgn_short;
            result.rayleigh_min = result.rayleigh_max = entry->rayleigh_short;
            strcpy(result.description, "Short LDPC (16200)");
        } else {
            result.ldpc_length_known = true;
            result.awgn_min = result.awgn_max = entry->awgn_long;
            result.rayleigh_min = result.rayleigh_max = entry->rayleigh_long;
            strcpy(result.description, "Long LDPC (64800) - Short unavailable");
        }
    } else if (ldpc_length == 1) {
        result.ldpc_length_known = true;
        result.awgn_min = result.awgn_max = entry->awgn_long;
        result.rayleigh_min = result.rayleigh_max = entry->rayleigh_long;
        strcpy(result.description, "Long LDPC (64800)");
    } else {
        result.ldpc_length_known = false;
        
        result.awgn_min = entry->awgn_long;
        result.awgn_max = entry->awgn_long;
        if (entry->awgn_short != 0.0) {
            if (entry->awgn_short < result.awgn_min) result.awgn_min = entry->awgn_short;
            if (entry->awgn_short > result.awgn_max) result.awgn_max = entry->awgn_short;
        }
        
        result.rayleigh_min = entry->rayleigh_long;
        result.rayleigh_max = entry->rayleigh_long;
        if (entry->rayleigh_short != 0.0) {
            if (entry->rayleigh_short < result.rayleigh_min) result.rayleigh_min = entry->rayleigh_short;
            if (entry->rayleigh_short > result.rayleigh_max) result.rayleigh_max = entry->rayleigh_short;
        }
        
        strcpy(result.description, "LDPC length unknown");
    }
    
    return result;
}

size_t b64_decoded_size_l1(const char *in) {
    size_t len;
    size_t ret;
    size_t i;

    if (in == NULL) return 0;

    len = strlen(in);
    ret = len / 4 * 3;

    for (i = len; i-- > 0;) {
        if (in[i] == '=') {
            ret--;
        } else {
            break;
        }
    }
    return ret;
}

int b64_isvalidchar_l1(char c) {
    if (c >= '0' && c <= '9') return 1;
    if (c >= 'A' && c <= 'Z') return 1;
    if (c >= 'a' && c <= 'z') return 1;
    if (c == '+' || c == '/' || c == '=') return 1;
    return 0;
}

int b64_decode_l1(const char *in, unsigned char *out, size_t outlen) {
    size_t len;
    size_t i;
    size_t j;
    int v;

    if (in == NULL || out == NULL) return 0;

    len = strlen(in);
    if (outlen < b64_decoded_size_l1(in) || len % 4 != 0) return 0;

    for (i = 0; i < len; i++) {
        if (!b64_isvalidchar_l1(in[i])) {
            return 0;
        }
    }

    for (i = 0, j = 0; i < len; i += 4, j += 3) {
        v = b64invs[in[i] - 43];
        v = (v << 6) | b64invs[in[i + 1] - 43];
        v = in[i + 2] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 2] - 43];
        v = in[i + 3] == '=' ? v << 6 : (v << 6) | b64invs[in[i + 3] - 43];

        out[j] = (v >> 16) & 0xFF;
        if (in[i + 2] != '=') out[j + 1] = (v >> 8) & 0xFF;
        if (in[i + 3] != '=') out[j + 2] = v & 0xFF;
    }

    return 1;
}

// get_bits function from l1dump.c
static int get_bits(int count) {
    int i;
    long value = 0;
    
    if (bits_index + count > sizeof(bits)) {
        return 0;
    }

    for (i = count; i > 0; i--) {
        value |= bits[bits_index++] << (i - 1);
    }
    return value;
}

/*
 * calculate_atsc3_bitrate_l1
 * Calculates the bitrate for a given PLP based on L1 signaling parameters.
 * Adapted from atsc3rate() in l1dump.c
 */
double calculate_atsc3_bitrate_l1(int fft_size_enum, int guardinterval, int numpayloadsyms, int numpreamblesyms, int rate, int constellation, int framesize, int pilotpattern, int firstsbs, int cred, int pilotboost, int paprmode, int ti_mode, int fec_blocks, int l1_detail_cells, int subframe, int num_subframes, struct subframe_info_t *subframe_info_arr, int frame_length_mode, int frame_length, int excess_samples, long plp_size_cells)
{
    int mod;
    double kbch, fecsize, fecrate, bitrate;
    double TF = 0.0, T, TS, TB;

    // --- Determine FEC parameters ---
    if (framesize == FECFRAME_NORMAL) { // 64K LDPC
        fecsize = 64800.0;
        switch (rate) {
            case C2_15: kbch = 8448; break;
            case C3_15: kbch = 12768; break;
            case C4_15: kbch = 17088; break;
            case C5_15: kbch = 21408; break;
            case C6_15: kbch = 25728; break;
            case C7_15: kbch = 30048; break;
            case C8_15: kbch = 34368; break;
            case C9_15: kbch = 38688; break;
            case C10_15: kbch = 43008; break;
            case C11_15: kbch = 47328; break;
            case C12_15: kbch = 51648; break;
            case C13_15: kbch = 55968; break;
            default: kbch = 0; break;
        }
    } else { // 16K LDPC
        fecsize = 16200.0;
        switch (rate) {
            case C2_15: kbch = 1992; break;
            case C3_15: kbch = 3072; break;
            case C4_15: kbch = 4152; break;
            case C5_15: kbch = 5232; break;
            case C6_15: kbch = 6312; break;
            case C7_15: kbch = 7392; break;
            case C8_15: kbch = 8472; break;
            case C9_15: kbch = 9552; break;
            case C10_15: kbch = 10632; break;
            case C11_15: kbch = 11712; break;
            case C12_15: kbch = 12792; break;
            case C13_15: kbch = 13872; break;
            default: kbch = 0; break;
        }
    }
    if (kbch == 0) return 0.0;

    // --- Determine modulation ---
    switch (constellation) {
        case MOD_QPSK: mod = 2; break;
        case MOD_16QAM: mod = 4; break;
        case MOD_64QAM: mod = 6; break;
        case MOD_256QAM: mod = 8; break;
        case MOD_1024QAM: mod = 10; break;
        case MOD_4096QAM: mod = 12; break;
        default: return 0.0;
    }

    // --- Calculate Frame Time (TF) ---
    T = 1.0 / (384000.0 * 18.0);
    TB = 1.0 / 6144000.0;

    if (frame_length_mode == 0) { // Time-aligned
        TF = frame_length * 5.0;
    } else { // Symbol-aligned
        for (int n = 0; n < num_subframes; n++) {
            int current_fft_size_enum = (n == 0) ? subframe_info_arr[0].fft_size : subframe_info_arr[n].fft_size;
            int current_gi_enum = (n == 0) ? subframe_info_arr[0].guard_interval : subframe_info_arr[n].guard_interval;
            int current_fft_val = (current_fft_size_enum == FFTSIZE_8K) ? 8192 : ((current_fft_size_enum == FFTSIZE_16K) ? 16384 : 32768);
            
            int guard_interval_val = 0;
            switch(current_gi_enum) {
                case GI_1_192: guard_interval_val = 192; break;
                case GI_2_384: guard_interval_val = 384; break;
                case GI_3_512: guard_interval_val = 512; break;
                case GI_4_768: guard_interval_val = 768; break;
                case GI_5_1024: guard_interval_val = 1024; break;
                case GI_6_1536: guard_interval_val = 1536; break;
                case GI_7_2048: guard_interval_val = 2048; break;
                case GI_8_2432: guard_interval_val = 2432; break;
                case GI_9_3072: guard_interval_val = 3072; break;
                case GI_10_3648: guard_interval_val = 3648; break;
                case GI_11_4096: guard_interval_val = 4096; break;
                case GI_12_4864: guard_interval_val = 4864; break;
            }

            int symbols = (n == 0) ? subframe_info_arr[n].num_ofdm_symbols + subframe_info_arr[n].num_preamble_symbols : subframe_info_arr[n].num_ofdm_symbols;
            TS = (T * (current_fft_val + guard_interval_val)) * 1000.0;
            TF += (symbols * TS);
            if (n == 0) {
                TF += (3072.0 * 4 * TB * 1000.0);
            }
        }
    }

    if (TF == 0.0) return 0.0;

    fecrate = kbch / fecsize;
    bitrate = (1000.0 / TF) * (plp_size_cells * mod * fecrate);

    return bitrate;
} 


void parse_l1_data_l1(const unsigned char* data, size_t len, char** display_lines, int* line_count, int max_lines, struct l1_parse_context* context) {
    long value;
    int i, j, k;
    
    // L1B Parameters
    int l1b_version, l1b_time_info_flag, l1b_papr_reduction, l1b_frame_length_mode;
    int l1b_frame_length = 0, l1b_excess_samples_per_symbol = 0;
    int l1b_num_subframes, l1b_l1_detail_size_bytes, l1b_l1_detail_total_cells;
    int l1b_first_sub_mimo, l1b_first_sub_sbs_first, l1b_first_sub_sbs_last;
    int l1b_first_sub_mimo_mixed = 0;

    // L1D Parameters
    int l1d_version, l1d_num_rf, l1d_mimo = 0, l1d_sbs_first = 0, l1d_sbs_last = 0;
    int l1d_num_plp = 0, l1d_plp_layer, l1d_plp_mod = 0, l1d_plp_TI_mode;
    int l1d_plp_num_channel_bonded, l1d_plp_HTI_inter_subframe, l1d_plp_HTI_num_ti_blocks;
    int l1d_mimo_mixed;

    // Structs for bitrate calculation
    struct subframe_info_t subframe_info[257] = {0};
    struct plp_info_t plp_info[MAX_PLPS] = {0};
    
    struct l1_detail_info info_temp = {display_lines, *line_count, max_lines, *context};
    
    // Populate the bit buffer
    bits_index = 0;
    int bit_count = 0;
    for (i = 0; i < len && bit_count < sizeof(bits); i++) {
        for (int n = 7; n >= 0 && bit_count < sizeof(bits); n--) {
            bits[bit_count++] = (data[i] & (1 << n)) ? 1 : 0;
        }
    }
    
    add_line(&info_temp, "--- L1-Basic Signaling ---");

    value = get_bits(3); add_line(&info_temp, "L1B_version: %ld", value); l1b_version = value;
    value = get_bits(1); add_line(&info_temp, "L1B_mimo_scattered_pilot_encoding: %s", value == 0 ? "Walsh-Hadamard" : "Null pilots");
    value = get_bits(1); add_line(&info_temp, "L1B_lls_flag: %s", value == 0 ? "No LLS" : "LLS present");
    value = get_bits(2); l1b_time_info_flag = value;
    switch (value) {
        case 0: add_line(&info_temp, "L1B_time_info_flag: Not included"); break;
        case 1: add_line(&info_temp, "L1B_time_info_flag: ms precision"); break;
        case 2: add_line(&info_temp, "L1B_time_info_flag: us precision"); break;
        case 3: add_line(&info_temp, "L1B_time_info_flag: ns precision"); break;
    }
    value = get_bits(1); add_line(&info_temp, "L1B_return_channel_flag: %ld", value);
    value = get_bits(2); l1b_papr_reduction = value & 1;
    switch (value) {
        case 0: add_line(&info_temp, "L1B_papr_reduction: None"); break;
        case 1: add_line(&info_temp, "L1B_papr_reduction: Tone reservation only"); break;
        case 2: add_line(&info_temp, "L1B_papr_reduction: ACE only"); break;
        case 3: add_line(&info_temp, "L1B_papr_reduction: Both TR and ACE"); break;
    }
    value = get_bits(1); l1b_frame_length_mode = value;
    if (value == 0) {
        add_line(&info_temp, "L1B_frame_length_mode: Time-aligned");
        value = get_bits(10); add_line(&info_temp, "  L1B_frame_length: %ld", value); l1b_frame_length = value;
        value = get_bits(13); add_line(&info_temp, "  L1B_excess_samples_per_symbol: %ld", value); l1b_excess_samples_per_symbol = value;
    } else {
        add_line(&info_temp, "L1B_frame_length_mode: Symbol-aligned");
        value = get_bits(16); add_line(&info_temp, "  L1B_time_offset: %ld", value);
        value = get_bits(7); add_line(&info_temp, "  L1B_additional_samples: %ld", value);
    }
    value = get_bits(8); add_line(&info_temp, "L1B_num_subframes: %ld", value + 1); l1b_num_subframes = value;
    value = get_bits(3); add_line(&info_temp, "L1B_preamble_num_symbols: %ld", value + 1); subframe_info[0].num_preamble_symbols = value + 1;
    value = get_bits(3); add_line(&info_temp, "L1B_preamble_reduced_carriers: %ld", value);
    value = get_bits(2); add_line(&info_temp, "L1B_L1_Detail_content_tag: %ld", value);
    value = get_bits(13); add_line(&info_temp, "L1B_L1_Detail_size_bytes: %ld", value); l1b_l1_detail_size_bytes = value;
    value = get_bits(3); add_line(&info_temp, "L1B_L1_Detail_fec_type: Mode %ld", value + 1);
    value = get_bits(2); add_line(&info_temp, "L1B_L1_additional_parity_mode: K=%ld", value);
    value = get_bits(19); add_line(&info_temp, "L1B_L1_Detail_total_cells: %ld", value); l1b_l1_detail_total_cells = value;
    value = get_bits(1); add_line(&info_temp, "L1B_first_sub_mimo: %s", value == 0 ? "No MIMO" : "MIMO"); l1b_first_sub_mimo = value;
    value = get_bits(2); add_line(&info_temp, "L1B_first_sub_miso: %ld", value);
    value = get_bits(2); subframe_info[0].fft_size = value; add_line(&info_temp, "L1B_first_sub_fft_size: %s", (value < 3) ? (value==0?"8K":value==1?"16K":"32K") : "Reserved");
    value = get_bits(3); subframe_info[0].reduced_carriers = value; add_line(&info_temp, "L1B_first_sub_reduced_carriers: %ld", value);
    value = get_bits(4); subframe_info[0].guard_interval = value;
    switch(value) {
        case GI_1_192: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_1_192"); break;
        case GI_2_384: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_2_384"); break;
        case GI_3_512: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_3_512"); break;
        case GI_4_768: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_4_768"); break;
        case GI_5_1024: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_5_1024"); break;
        case GI_6_1536: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_6_1536"); break;
        case GI_7_2048: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_7_2048"); break;
        case GI_8_2432: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_8_2432"); break;
        case GI_9_3072: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_9_3072"); break;
        case GI_10_3648: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_10_3648"); break;
        case GI_11_4096: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_11_4096"); break;
        case GI_12_4864: add_line(&info_temp, "L1B_first_sub_guard_interval: GI_12_4864"); break;
        default: add_line(&info_temp, "L1B_first_sub_guard_interval: Reserved (%ld)", value); break;
    }
    value = get_bits(11); add_line(&info_temp, "L1B_first_sub_num_ofdm_symbols: %ld", value + 1); subframe_info[0].num_ofdm_symbols = value + 1;
    value = get_bits(5); add_line(&info_temp, "L1B_first_sub_scattered_pilot_pattern: %ld", value); subframe_info[0].scattered_pilot_pattern = value;
    value = get_bits(3); add_line(&info_temp, "L1B_first_sub_scattered_pilot_boost: %ld", value); subframe_info[0].scattered_pilot_boost = value;
    value = get_bits(1); add_line(&info_temp, "L1B_first_sub_sbs_first: %ld", value); l1b_first_sub_sbs_first = value; subframe_info[0].sbs_first = value;
    value = get_bits(1); add_line(&info_temp, "L1B_first_sub_sbs_last: %ld", value); l1b_first_sub_sbs_last = value; subframe_info[0].sbs_last = value;
    if (l1b_version >= 1) {
        value = get_bits(1); add_line(&info_temp, "L1B_first_sub_mimo_mixed: %ld", value); l1b_first_sub_mimo_mixed = value;
        get_bits(47);
    } else {
        get_bits(48);
    }
    value = get_bits(32); add_line(&info_temp, "L1B_crc: 0x%08lx", value);
    
    add_line(&info_temp, " ");
    add_line(&info_temp, "--- L1-Detail Signaling ---");
    
    value = get_bits(4); add_line(&info_temp, "L1D_version: %ld", value); l1d_version = value;
    value = get_bits(3); add_line(&info_temp, "L1D_num_rf: %ld", value); l1d_num_rf = value;
    for (i = 1; i <= l1d_num_rf; i++) {
        value = get_bits(16); add_line(&info_temp, "  L1D_bonded_bsid: 0x%04lx", value);
        get_bits(3);
    }
    if (l1b_time_info_flag != 0) {
        value = get_bits(32); add_line(&info_temp, "L1D_time_sec: %ld", value);
        value = get_bits(10); add_line(&info_temp, "L1D_time_msec: %ld", value);
        if (l1b_time_info_flag > 1) {
            value = get_bits(10); add_line(&info_temp, "L1D_time_usec: %ld", value);
            if (l1b_time_info_flag > 2) {
                value = get_bits(10); add_line(&info_temp, "L1D_time_nsec: %ld", value);
            }
        }
    }
    
    // Continue with subframes parsing
    for (i = 0; i <= l1b_num_subframes; i++) {
        add_line(&info_temp, " "); 
        add_line(&info_temp, "Subframe #%d:", i);
        if (i > 0) {
            value = get_bits(1); add_line(&info_temp, "  L1D_mimo: %s", value == 0 ? "No MIMO" : "MIMO"); l1d_mimo = value;
            value = get_bits(2); add_line(&info_temp, "  L1D_miso: %ld", value);
            value = get_bits(2); subframe_info[i].fft_size = value; add_line(&info_temp, "  L1D_fft_size: %s", (value < 3) ? (value==0?"8K":value==1?"16K":"32K") : "Reserved");
            value = get_bits(3); subframe_info[i].reduced_carriers = value; add_line(&info_temp, "  L1D_reduced_carriers: %ld", value);
            value = get_bits(4); subframe_info[i].guard_interval = value;
            switch(value) {
                case GI_1_192: add_line(&info_temp, "  L1D_guard_interval: GI_1_192"); break;
                case GI_2_384: add_line(&info_temp, "  L1D_guard_interval: GI_2_384"); break;
                case GI_3_512: add_line(&info_temp, "  L1D_guard_interval: GI_3_512"); break;
                case GI_4_768: add_line(&info_temp, "  L1D_guard_interval: GI_4_768"); break;
                case GI_5_1024: add_line(&info_temp, "  L1D_guard_interval: GI_5_1024"); break;
                case GI_6_1536: add_line(&info_temp, "  L1D_guard_interval: GI_6_1536"); break;
                case GI_7_2048: add_line(&info_temp, "  L1D_guard_interval: GI_7_2048"); break;
                case GI_8_2432: add_line(&info_temp, "  L1D_guard_interval: GI_8_2432"); break;
                case GI_9_3072: add_line(&info_temp, "  L1D_guard_interval: GI_9_3072"); break;
                case GI_10_3648: add_line(&info_temp, "  L1D_guard_interval: GI_10_3648"); break;
                case GI_11_4096: add_line(&info_temp, "  L1D_guard_interval: GI_11_4096"); break;
                case GI_12_4864: add_line(&info_temp, "  L1D_guard_interval: GI_12_4864"); break;
                default: add_line(&info_temp, "  L1D_guard_interval: Reserved (%ld)", value); break;
            }
            value = get_bits(11); add_line(&info_temp, "  L1D_num_ofdm_symbols: %ld", value + 1); subframe_info[i].num_ofdm_symbols = value + 1;
            value = get_bits(5); add_line(&info_temp, "  L1D_scattered_pilot_pattern: %ld", value); subframe_info[i].scattered_pilot_pattern = value;
            value = get_bits(3); add_line(&info_temp, "  L1D_scattered_pilot_boost: %ld", value); subframe_info[i].scattered_pilot_boost = value;
            value = get_bits(1); add_line(&info_temp, "  L1D_sbs_first: %ld", value); l1d_sbs_first = value; subframe_info[i].sbs_first = value;
            value = get_bits(1); add_line(&info_temp, "  L1D_sbs_last: %ld", value); l1d_sbs_last = value; subframe_info[i].sbs_last = value;
        }
        if (l1b_num_subframes > 0) {
            value = get_bits(1); add_line(&info_temp, "  L1D_subframe_multiplex: %ld", value);
        }
        value = get_bits(1); add_line(&info_temp, "  L1D_frequency_interleaver: %s", value == 0 ? "Preamble Only" : "All Symbols");
        if ((i == 0 && (l1b_first_sub_sbs_first == 1 || l1b_first_sub_sbs_last == 1)) || (i > 0 && (l1d_sbs_first == 1 || l1d_sbs_last == 1))) {
            value = get_bits(13); add_line(&info_temp, "  L1D_sbs_null_cells: %ld", value);
        }
        value = get_bits(6); add_line(&info_temp, "  L1D_num_plp: %ld", value + 1); l1d_num_plp = value;
        
        // Parse PLPs for this subframe
        for (j = 0; j <= l1d_num_plp; j++) {
            add_line(&info_temp, "    PLP #%d:", j);
            value = get_bits(6); add_line(&info_temp, "      L1D_plp_id: %ld", value); plp_info[j].plp_id = value;
            value = get_bits(1); add_line(&info_temp, "      L1D_plp_lls_flag: %ld", value);
            value = get_bits(2); add_line(&info_temp, "      L1D_plp_layer: %s", (value==0) ? "Core" : (value==1 ? "Enhanced" : "Reserved")); l1d_plp_layer = value;
            value = get_bits(24); add_line(&info_temp, "      L1D_plp_start: %ld", value);
            value = get_bits(24); add_line(&info_temp, "      L1D_plp_size: %ld", value); plp_info[j].size = value;
            value = get_bits(2); add_line(&info_temp, "      L1D_plp_scrambler_type: %s", (value==0) ? "PRBS" : "Reserved");
            value = get_bits(4); plp_info[j].fec_type = !(value & 1);
            switch (value) {
                case 0: add_line(&info_temp, "      L1D_plp_fec_type: BCH + 16K LDPC"); break;
                case 1: add_line(&info_temp, "      L1D_plp_fec_type: BCH + 64K LDPC"); break;
                case 2: add_line(&info_temp, "      L1D_plp_fec_type: CRC + 16K LDPC"); break;
                case 3: add_line(&info_temp, "      L1D_plp_fec_type: CRC + 64K LDPC"); break;
                case 4: add_line(&info_temp, "      L1D_plp_fec_type: 16K LDPC only"); break;
                case 5: add_line(&info_temp, "      L1D_plp_fec_type: 64K LDPC only"); break;
                default: add_line(&info_temp, "      L1D_plp_fec_type: Reserved"); break;
            }
            if (context && !context->ldpc_info_available) {
                context->ldpc_info_available = true;
                if (value == 0 || value == 2 || value == 4) {
                    context->ldpc_length = 0;  // 16K LDPC (short)
                } else if (value == 1 || value == 3 || value == 5) {
                    context->ldpc_length = 1;  // 64K LDPC (long)
                }
            }
            if (value <= 5) {
                value = get_bits(4); l1d_plp_mod = value; plp_info[j].mod = value;
                switch (value) {
                    case MOD_QPSK: add_line(&info_temp, "      L1D_plp_mod: QPSK"); break;
                    case MOD_16QAM: add_line(&info_temp, "      L1D_plp_mod: 16QAM"); break;
                    case MOD_64QAM: add_line(&info_temp, "      L1D_plp_mod: 64QAM"); break;
                    case MOD_256QAM: add_line(&info_temp, "      L1D_plp_mod: 256QAM"); break;
                    case MOD_1024QAM: add_line(&info_temp, "      L1D_plp_mod: 1024QAM"); break;
                    case MOD_4096QAM: add_line(&info_temp, "      L1D_plp_mod: 4096QAM"); break;
                    default: add_line(&info_temp, "      L1D_plp_mod: Reserved"); break;
                }
                value = get_bits(4); plp_info[j].cod = value;
                switch (value) {
                    case C2_15: add_line(&info_temp, "      L1D_plp_cod: 2/15"); break;
                    case C3_15: add_line(&info_temp, "      L1D_plp_cod: 3/15"); break;
                    case C4_15: add_line(&info_temp, "      L1D_plp_cod: 4/15"); break;
                    case C5_15: add_line(&info_temp, "      L1D_plp_cod: 5/15"); break;
                    case C6_15: add_line(&info_temp, "      L1D_plp_cod: 6/15"); break;
                    case C7_15: add_line(&info_temp, "      L1D_plp_cod: 7/15"); break;
                    case C8_15: add_line(&info_temp, "      L1D_plp_cod: 8/15"); break;
                    case C9_15: add_line(&info_temp, "      L1D_plp_cod: 9/15"); break;
                    case C10_15: add_line(&info_temp, "      L1D_plp_cod: 10/15"); break;
                    case C11_15: add_line(&info_temp, "      L1D_plp_cod: 11/15"); break;
                    case C12_15: add_line(&info_temp, "      L1D_plp_cod: 12/15"); break;
                    case C13_15: add_line(&info_temp, "      L1D_plp_cod: 13/15"); break;
                    default: add_line(&info_temp, "      L1D_plp_cod: Reserved"); break;
                }
            }
            value = get_bits(2); l1d_plp_TI_mode = value; plp_info[j].ti_mode = value;
            switch (value) {
                case 0: add_line(&info_temp, "      L1D_plp_TI_mode: No TI"); break;
                case 1: add_line(&info_temp, "      L1D_plp_TI_mode: CTI"); break;
                case 2: add_line(&info_temp, "      L1D_plp_TI_mode: HTI"); break;
                default: add_line(&info_temp, "      L1D_plp_TI_mode: Reserved"); break;
            }
            if (l1d_plp_TI_mode == 0) { 
                value = get_bits(15); add_line(&info_temp, "      L1D_plp_fec_block_start: %ld", value); 
            } else if (l1d_plp_TI_mode == 1) { 
                value = get_bits(22); add_line(&info_temp, "      L1D_plp_CTI_fec_block_start: %ld", value); 
            }
            if (l1d_num_rf > 0) {
                value = get_bits(3); add_line(&info_temp, "      L1D_plp_num_channel_bonded: %ld", value); l1d_plp_num_channel_bonded = value;
                if (l1d_plp_num_channel_bonded > 0) {
                    value = get_bits(2); add_line(&info_temp, "      L1D_plp_channel_bonding_format: %ld", value);
                    for (k = 0; k < l1d_plp_num_channel_bonded; k++) {
                        value = get_bits(3); add_line(&info_temp, "        L1D_plp_bonded_rf_id: %ld", value);
                    }
                }
            }
            if ((i == 0 && l1b_first_sub_mimo == 1) || (i > 0 && l1d_mimo)) {
                value = get_bits(1); add_line(&info_temp, "      L1D_plp_mimo_stream_combining: %ld", value);
                value = get_bits(1); add_line(&info_temp, "      L1D_plp_mimo_IQ_interleaving: %ld", value);
                value = get_bits(1); add_line(&info_temp, "      L1D_plp_mimo_PH: %ld", value);
            }
            if (l1d_plp_layer == 0) {
                value = get_bits(1);
                if (value == 0) { 
                    add_line(&info_temp, "      L1D_plp_type: non-dispersed"); 
                } else {
                    add_line(&info_temp, "      L1D_plp_type: dispersed");
                    value = get_bits(14); add_line(&info_temp, "      L1D_plp_num_subslices: %ld", value + 1);
                    value = get_bits(24); add_line(&info_temp, "      L1D_plp_subslice_interval: %ld", value);
                }
                if ((l1d_plp_TI_mode == 1 || l1d_plp_TI_mode == 2) && l1d_plp_mod == 0) {
                    value = get_bits(1);
                    add_line(&info_temp, "      L1D_plp_TI_extended_interleaving: %ld", value);
                }
                if (l1d_plp_TI_mode == 1) {
                    value = get_bits(3); add_line(&info_temp, "      L1D_plp_CTI_depth: %ld", value);
                    value = get_bits(11); add_line(&info_temp, "      L1D_plp_CTI_start_row: %ld", value);
                } else if (l1d_plp_TI_mode == 2) {
                    value = get_bits(1); add_line(&info_temp, "      L1D_plp_HTI_inter_subframe: %ld", value); l1d_plp_HTI_inter_subframe = value;
                    value = get_bits(4); add_line(&info_temp, "      L1D_plp_HTI_num_ti_blocks: %ld", value + 1); l1d_plp_HTI_num_ti_blocks = value;
                    value = get_bits(12); add_line(&info_temp, "      L1D_plp_HTI_num_fec_blocks_max: %ld", value + 1);
                    if (l1d_plp_HTI_inter_subframe == 0) {
                        value = get_bits(12); add_line(&info_temp, "      L1D_plp_HTI_num_fec_blocks: %ld", value + 1); plp_info[j].HTI_num_fec_blocks = value + 1;
                    } else {
                        for (k = 0; k <= l1d_plp_HTI_num_ti_blocks; k++) {
                            value = get_bits(12); add_line(&info_temp, "        L1D_plp_HTI_num_fec_blocks: %ld", value + 1);
                        }
                    }
                    value = get_bits(1); add_line(&info_temp, "      L1D_plp_HTI_cell_interleaver: %ld", value);
                }
            } else {
                value = get_bits(5); add_line(&info_temp, "      L1D_plp_ldm_injection_level: %ld", value);
            }
            
            // Calculate and add bitrate info
            double bitrate = calculate_atsc3_bitrate_l1(
                subframe_info[i].fft_size, subframe_info[i].guard_interval, subframe_info[i].num_ofdm_symbols,
                (i==0 ? subframe_info[0].num_preamble_symbols : 0),
                plp_info[j].cod, plp_info[j].mod, plp_info[j].fec_type,
                subframe_info[i].scattered_pilot_pattern, subframe_info[i].sbs_first,
                subframe_info[i].reduced_carriers, subframe_info[i].scattered_pilot_boost,
                l1b_papr_reduction, plp_info[j].ti_mode, plp_info[j].HTI_num_fec_blocks,
                l1b_l1_detail_total_cells, i, l1b_num_subframes + 1, subframe_info,
                l1b_frame_length_mode, l1b_frame_length, l1b_excess_samples_per_symbol, plp_info[j].size
            );
            if (bitrate > 0) {
                add_line(&info_temp, "      -> PLP Bitrate: %.3f Mbps", bitrate / 1000000.0);
            }
        }
    }
    
    // Handle remaining L1D fields
    if (l1d_version >= 1) {
        value = get_bits(16); add_line(&info_temp, "L1D_bsid: 0x%04lx", value);
    }
    if (l1d_version >= 2) {
        for (i = 0; i <= l1b_num_subframes; i++) {
            if (i > 0) {
                value = get_bits(1); add_line(&info_temp, "  Subframe #%d L1D_mimo_mixed: %ld", i, value); l1d_mimo_mixed = value;
            }
            if ((i == 0 && l1b_first_sub_mimo_mixed == 1) || (i > 0 && l1d_mimo_mixed == 1)) {
                for (j = 0; j <= l1d_num_plp; j++) {
                    value = get_bits(1); add_line(&info_temp, "    PLP #%d L1D_plp_mimo: %ld", j, value);
                    if (value == 1) {
                        value = get_bits(1); add_line(&info_temp, "      L1D_plp_mimo_stream_combining: %ld", value);
                        value = get_bits(1); add_line(&info_temp, "      L1D_plp_mimo_IQ_interleaving: %ld", value);
                        value = get_bits(1); add_line(&info_temp, "      L1D_plp_mimo_PH: %ld", value);
                    }
                }
            }
        }
    }
    
    // Skip any remaining bits before CRC
    if ((((l1b_l1_detail_size_bytes * 8) - 32) - (bits_index - 200)) > 0) {
        get_bits(((l1b_l1_detail_size_bytes * 8) - 32) - (bits_index - 200));
    }
    value = get_bits(32); add_line(&info_temp, "L1D_crc: 0x%08lx", value);
    
    // Update context and line count
    *context = info_temp.context;
    *line_count = info_temp.line_count;
}

void update_plp_snr_info_l1(char** display_lines, int line_count, int ldpc_length) {
    for (int i = 0; i < line_count; i++) {
        char* line = display_lines[i];
        if (strstr(line, "mod=") && strstr(line, "cod=")) {
            char *mod_ptr = strstr(line, "mod=");
            char *cod_ptr = strstr(line, "cod=");
            
            if (mod_ptr && cod_ptr) {
                char raw_mod_str[16] = {0}, normalized_mod_str[16] = {0}, cod_str[8] = {0};
                
                const char *mod_val_start = mod_ptr + 4;
                const char *mod_val_end = strchr(mod_val_start, ' ');
                size_t mod_len = mod_val_end ? (size_t)(mod_val_end - mod_val_start) : strlen(mod_val_start);
                if (mod_len < sizeof(raw_mod_str)) {
                    strncpy(raw_mod_str, mod_val_start, mod_len);
                    raw_mod_str[mod_len] = '\0';
                    normalize_mod_str_l1(raw_mod_str, normalized_mod_str, sizeof(normalized_mod_str));
                }

                const char *cod_val_start = cod_ptr + 4;
                const char *cod_val_end = strchr(cod_val_start, ' ');
                size_t cod_len = cod_val_end ? (size_t)(cod_val_end - cod_val_start) : strlen(cod_val_start);
                if (cod_len < sizeof(cod_str)) {
                    strncpy(cod_str, cod_val_start, cod_len);
                    cod_str[cod_len] = '\0';
                }
                
                if (i + 1 < line_count && strstr(display_lines[i + 1], "-> Required SNR:")) {
                    struct snr_pair_result snr_result = get_snr_pair_for_modcod_l1(normalized_mod_str, cod_str, ldpc_length);
                    if (snr_result.found) {
                        free(display_lines[i + 1]);
                        
                        char snr_line[256] = {0};
                        if (snr_result.ldpc_length_known) {
                            sprintf(snr_line, "  -> Required SNR: AWGN %.2f dB, Rayleigh %.2f dB",
                                    snr_result.awgn_min, snr_result.rayleigh_min);
                        } else {
                            sprintf(snr_line, "  -> Required SNR: AWGN %.2f to %.2f dB, Rayleigh %.2f to %.2f dB", 
                                    snr_result.awgn_min, snr_result.awgn_max, 
                                    snr_result.rayleigh_min, snr_result.rayleigh_max);
                        }
                        display_lines[i + 1] = strdup(snr_line);
                    }
                }
            }
        }
    }
}

int collect_atsc3_details(struct hdhomerun_device_t *hd, int tuner_index, struct l1_detail_info* detail_info) {
    if (!hd || !detail_info) return -1;
    
    // Reset line count
    detail_info->line_count = 0;
    detail_info->context.ldpc_info_available = false;
    detail_info->context.ldpc_length = -1;
    
    char *plpinfo_str_orig;
    char *streaminfo_str_orig;
    
    // Get PLP info
    if (hdhomerun_device_get_tuner_plpinfo(hd, &plpinfo_str_orig) <= 0) {
        return -1; // No PLP info available
    }
    char *plpinfo_copy = strdup(plpinfo_str_orig);

    // Get stream info
    if (hdhomerun_device_get_tuner_streaminfo(hd, &streaminfo_str_orig) <= 0) {
        streaminfo_str_orig = "";
    }
    char *streaminfo_copy = strdup(streaminfo_str_orig);

    // Add initial spacing
    if (detail_info->line_count < detail_info->max_lines) {
        detail_info->display_lines[detail_info->line_count++] = strdup(" ");
    }
    
    // Add firmware version
    char *version_str;
    if (hdhomerun_device_get_var(hd, "/sys/version", &version_str, NULL) > 0) {
        char version_line[128];
        sprintf(version_line, "Firmware Version: %s", version_str);
        detail_info->display_lines[detail_info->line_count++] = strdup(version_line);
        
        if (detail_info->line_count < detail_info->max_lines) {
            detail_info->display_lines[detail_info->line_count++] = strdup(" ");
        }
    }

    // Add BSID and TSID info
    long bsid = -999;
    long tsid = -999;

    char *fresh_plpinfo;
    if (hdhomerun_device_get_tuner_plpinfo(hd, &fresh_plpinfo) > 0) {
        bsid = parse_status_value_l1(fresh_plpinfo, "bsid=");
    }

    char *fresh_streaminfo;
    if (hdhomerun_device_get_tuner_streaminfo(hd, &fresh_streaminfo) > 0) {
        tsid = parse_status_value_l1(fresh_streaminfo, "tsid=");
    }

    if (bsid != -999) {
        char bsid_line[64];
        sprintf(bsid_line, "L1D BSID: %ld (0x%lX)", bsid, bsid);
        detail_info->display_lines[detail_info->line_count++] = strdup(bsid_line);
    } else {
        detail_info->display_lines[detail_info->line_count++] = strdup("L1D BSID: Not set");
    }

    if (tsid != -999) {
        char tsid_line[64];
        sprintf(tsid_line, "SLT TSID: %ld (0x%lX)", tsid, tsid);
        detail_info->display_lines[detail_info->line_count++] = strdup(tsid_line);
    } else {
        detail_info->display_lines[detail_info->line_count++] = strdup("SLT TSID: Not set");
    }

    if (detail_info->line_count < detail_info->max_lines) {
        detail_info->display_lines[detail_info->line_count++] = strdup(" ");
    }

    // Process PLP info
    if (plpinfo_copy) {
        char *line = strtok(plpinfo_copy, "\n");
        while (line != NULL && detail_info->line_count < detail_info->max_lines) {
            if (strncmp(line, "bsid=", 5) != 0) {
                detail_info->display_lines[detail_info->line_count++] = strdup(line);
                
                char *mod_ptr = strstr(line, "mod=");
                char *cod_ptr = strstr(line, "cod=");

                if (mod_ptr && cod_ptr && detail_info->line_count < detail_info->max_lines) {
                    char raw_mod_str[16] = {0}, normalized_mod_str[16] = {0}, cod_str[8] = {0};
                    
                    const char *mod_val_start = mod_ptr + 4;
                    const char *mod_val_end = strchr(mod_val_start, ' ');
                    size_t mod_len = mod_val_end ? (size_t)(mod_val_end - mod_val_start) : strlen(mod_val_start);
                    if (mod_len < sizeof(raw_mod_str)) {
                        strncpy(raw_mod_str, mod_val_start, mod_len);
                        raw_mod_str[mod_len] = '\0';
                        normalize_mod_str_l1(raw_mod_str, normalized_mod_str, sizeof(normalized_mod_str));
                    }

                    const char *cod_val_start = cod_ptr + 4;
                    const char *cod_val_end = strchr(cod_val_start, ' ');
                    size_t cod_len = cod_val_end ? (size_t)(cod_val_end - cod_val_start) : strlen(cod_val_start);
                    if (cod_len < sizeof(cod_str)) {
                        strncpy(cod_str, cod_val_start, cod_len);
                        cod_str[cod_len] = '\0';
                    }
                    
                    int ldpc_length = -1;  // Unknown by default
                    struct snr_pair_result snr_result = get_snr_pair_for_modcod_l1(normalized_mod_str, cod_str, ldpc_length);
                    if (snr_result.found) {
                        char snr_line[256] = {0};
                        if (snr_result.ldpc_length_known) {
                            sprintf(snr_line, "  -> Required SNR: AWGN %.2f dB, Rayleigh %.2f dB (%s)", 
                                    snr_result.awgn_min, snr_result.rayleigh_min, snr_result.description);
                        } else {
                            sprintf(snr_line, "  -> Required SNR: AWGN %.2f to %.2f dB, Rayleigh %.2f to %.2f dB", 
                            snr_result.awgn_min, snr_result.awgn_max, 
                            snr_result.rayleigh_min, snr_result.rayleigh_max);
                        }
                        detail_info->display_lines[detail_info->line_count++] = strdup(snr_line);
                    }
                }

                if (detail_info->line_count < detail_info->max_lines) {
                    detail_info->display_lines[detail_info->line_count++] = strdup(" ");
                }
            }
            line = strtok(NULL, "\n");
        }
    }

    // Add L1 Detail if available
    char *raw_status_str;
    struct hdhomerun_tuner_status_t status;
    bool has_db_values = false;
    if (hdhomerun_device_get_tuner_status(hd, &raw_status_str, &status) > 0) {
        if (parse_status_value_l1(raw_status_str, "ss=") != -999) has_db_values = true;
    }

    char *fresh_version_str;
    long version_num = 0;
    if (hdhomerun_device_get_var(hd, "/sys/version", &fresh_version_str, NULL) > 0) {
        char numeric_version_str[16] = {0};
        int i = 0;
        while(fresh_version_str[i] && isdigit((unsigned char)fresh_version_str[i]) && i < 15) {
            numeric_version_str[i] = fresh_version_str[i];
            i++;
        }
        version_num = atol(numeric_version_str);
    }
    
    if (has_db_values && version_num > 20250623) {
        char l1_path[64];
        sprintf(l1_path, "/tuner%d/l1detail", tuner_index);

        char *l1_detail_str;
        if (hdhomerun_device_get_var(hd, l1_path, &l1_detail_str, NULL) > 0) {
            // Add separator before L1 detail info
            if (detail_info->line_count < detail_info->max_lines - 3) {
                detail_info->display_lines[detail_info->line_count++] = strdup("__HLINE__");
                detail_info->display_lines[detail_info->line_count++] = strdup(" ");
            }

            size_t decoded_len = b64_decoded_size_l1(l1_detail_str);
            unsigned char *decoded_data = malloc(decoded_len);
            if (decoded_data) {
                if (b64_decode_l1(l1_detail_str, decoded_data, decoded_len)) {
                    parse_l1_data_l1(decoded_data, decoded_len, detail_info->display_lines, 
                                    &detail_info->line_count, detail_info->max_lines, &detail_info->context);
                    
                    // Update SNR info with LDPC-aware values
                    if (detail_info->context.ldpc_info_available) {
                        update_plp_snr_info_l1(detail_info->display_lines, detail_info->line_count, 
                                              detail_info->context.ldpc_length);
                    }
                }
                free(decoded_data);
            }
        }
    }

    free(streaminfo_copy);
    free(plpinfo_copy);
    return 0;
}

int save_atsc3_details_to_file(const char* filename, struct l1_detail_info* detail_info, const char* l1_detail_base64) {
    if (!filename || !detail_info) return -1;
    
    FILE *f = fopen(filename, "w");
    if (!f) return -1;
    
    for (int i = 0; i < detail_info->line_count; i++) {
        if (strcmp(detail_info->display_lines[i], "__HLINE__") == 0) {
            fprintf(f, "================================================================================\n");
        } else {
            fprintf(f, "%s\n", detail_info->display_lines[i]);
        }
    }
    
    // Add base64 L1 detail string at the end (for saved files only)
    if (l1_detail_base64 && strlen(l1_detail_base64) > 0) {
        fprintf(f, "\n");
        fprintf(f, "================================================================================\n\n");
        fprintf(f, "Raw L1 Detail (Base64):\n");
        fprintf(f, "%s\n", l1_detail_base64);
    }
    
    fclose(f);
    return 0;
}

int save_atsc3_details_auto(struct hdhomerun_device_t *hd, int tuner_index, const char* base_filename) {
    if (!hd || !base_filename) return -1;
    
    // Create detail info structure
    struct l1_detail_info* detail_info = create_l1_detail_info(MAX_DISPLAY_LINES);
    if (!detail_info) return -1;
    
    char *saved_l1_detail_str = NULL;
    
    // Collect the details
    int result = collect_atsc3_details(hd, tuner_index, detail_info);
    if (result != 0) {
        free_l1_detail_info(detail_info);
        return result;
    }
    
    // Capture L1 detail base64 string for file output
    char *version_str;
    long version_num = 0;
    if (hdhomerun_device_get_var(hd, "/sys/version", &version_str, NULL) > 0) {
        char numeric_version_str[16] = {0};
        int i = 0;
        while(version_str[i] && isdigit((unsigned char)version_str[i]) && i < 15) {
            numeric_version_str[i] = version_str[i];
            i++;
        }
        version_num = atol(numeric_version_str);
    }
    
    if (version_num > 20250623) {
        char l1_path[64];
        sprintf(l1_path, "/tuner%d/l1detail", tuner_index);
        char *l1_detail_str;
        if (hdhomerun_device_get_var(hd, l1_path, &l1_detail_str, NULL) > 0) {
            saved_l1_detail_str = strdup(l1_detail_str);
        }
    }
    
    // Create filename by replacing extension with .txt
    char details_filename[512];
    const char* last_dot = strrchr(base_filename, '.');
    if (last_dot) {
        size_t base_len = last_dot - base_filename;
        snprintf(details_filename, sizeof(details_filename), "%.*s.txt", (int)base_len, base_filename);
    } else {
        snprintf(details_filename, sizeof(details_filename), "%s.txt", base_filename);
    }
    
    // Save to file
    result = save_atsc3_details_to_file(details_filename, detail_info, saved_l1_detail_str);
    
    if (saved_l1_detail_str) {
        free(saved_l1_detail_str);
    }
    
    free_l1_detail_info(detail_info);
    return result;
}
