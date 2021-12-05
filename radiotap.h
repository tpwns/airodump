#pragma once
#include <cstdio>
#include <stdint.h>
#pragma pack(push,1)

typedef struct present_flags{
    uint8_t tsft:1;
    uint8_t flags:1;
    uint8_t rate:1;
    uint8_t channel:1;
    uint8_t fhss:1;
    uint8_t dbm_antenna_sig:1; // antenna signal awlays 5th bits
    uint8_t dbm_antenna_noise:1;
    uint8_t lock_quality:1;
    uint8_t tx_attenuation:1;
    uint8_t db_tx_attenuation:1;
    uint8_t dbm_tx_power:1;
    uint8_t antenna:1;
    uint8_t db_antenna_sig:1;
    uint8_t db_antenna_noise:1;
    uint8_t rx_flags:1;
    uint8_t padding:3;
    uint8_t channel_plus:1;
    uint8_t mcs_info:1;
    uint8_t a_mpdu_stat:1;
    uint8_t vht_info:1;
    uint8_t frame_timestamp:1;
    uint8_t he_info:1;
    uint8_t he_mu_info:1;
    uint8_t padding2:1;
    uint8_t zero_len_psdu:1;
    uint8_t l_sig:1;
    uint8_t reserved:1;
    uint8_t radiotap_ns_next:1;
    uint8_t vendor_ns_next:1;
    uint8_t ext:1;
}Present_flags;

typedef struct Flags{
    uint8_t cfp:1;
    uint8_t preamble:1;
    uint8_t wep:1;
    uint8_t fragmentation:1;
    uint8_t fcs_at_end:1;
    uint8_t data_pad:1;
    uint8_t bad_fcs:1;
    uint8_t short_gi:1;
}Flags;

typedef struct Channel_flags{
    uint8_t padding:4;
    uint8_t turbo:1;
    uint8_t cck:1;
    uint8_t ofdm:1;
    uint8_t two_ghz:1;
    uint8_t five_ghz:1;
    uint8_t passive:1;
    uint8_t dynamic_cck_ofdm:1;
    uint8_t gaussian_freq_shift_keying:1;
    uint8_t gsm:1;
    uint8_t static_turbo:1;
    uint8_t half_rate_chan:1;
    uint8_t quater_rate_chan:1;    
}Channel_flags;

struct RadiotapHeader {
    uint8_t version_;
    uint8_t pad_;
    uint16_t len_;
    present_flags present_flags_;

    uint16_t hd_len() { return len_; }

};

int get_radiotap_PWR (struct RadiotapHeader *rtHdr);

#pragma pack(pop)