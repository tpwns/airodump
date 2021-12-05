#include "radiotap.h"

int get_radiotap_PWR (struct RadiotapHeader *rtHdr)
{
    char * rt_iter;
    int pwr=0;

    rt_iter = (char *)(rtHdr + 1);
    rt_iter += 2*sizeof(present_flags);   //present flags가 항상 2개 더 붙는다?
    if (rtHdr->present_flags_.tsft==1){
        rt_iter += sizeof(uint64_t);
    }
    if( rtHdr->present_flags_.flags==1){
        rt_iter += sizeof(uint8_t);
    }
    if(rtHdr->present_flags_.rate==1){
        rt_iter += sizeof(uint8_t);
    }
    if(rtHdr->present_flags_.channel==1){
        rt_iter += sizeof(uint32_t); 
    }
    if(rtHdr->present_flags_.fhss==1){
        rt_iter += sizeof(uint8_t);
    }
    if(rtHdr->present_flags_.dbm_antenna_sig==1){
        pwr = (int)(*rt_iter);
        rt_iter += sizeof(uint8_t);
    }
    return pwr;
}
