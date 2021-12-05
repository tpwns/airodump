#pragma once
#include <cstdio>
#include "mac.h" 
#pragma pack(push,1)

struct BecaonMacHeader {
    uint16_t frame_control_;
    uint16_t duration_;
    Mac DA;
    Mac SA;
    Mac BSSID;
    uint16_t Seq_ctl;

    enum: uint16_t{
        type_beacon_frame = 0x8000
    };
};

struct BecaonBody_fixed {
    uint64_t timestamp;
    uint16_t interval;
    uint16_t capability;
};



#pragma pack(pop)