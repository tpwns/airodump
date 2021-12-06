#include <cstdio>
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>
#include <time.h>
#include <unistd.h>
#include "mac.h"
#include "radiotap.h"
#include "beaconframe.h"

using namespace std;


#pragma pack(push,1)

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump wlan0\n");
}

map<Mac,struct Airodump_values> APMap;
static std::mutex m;

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

struct Airodump_values{
    int pwr;
    string SSID;
    Mac BSSID;
    unsigned Beacons;
};

void dump(char* buf, int size) {
	int i;
	for (i = 0; i < size; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%02hhX ", buf[i]);
	}
	printf("\n");
}

void upLinePrompt(int count)
{
    for (int i = 0; i < count; ++i) {
        //printf("%c[2K",27);
        cout<<"\33[2K"; //line clear
        cout<<"\x1b[A"; //up line (ESC [ A) must be support VT100 escape seq
    }
}

void channel_hopping(char *dev)
{
    int chan_num[14]= {1,7,13,2,8,3,14,9,4,10,5,11,6,12};
    
    for(int i=0;;i++){
        if(i>=14){
            i=0;
        }

        string command;
        command = "sudo iwconfig ";
        command.append(string(dev));
        command.append(" channel ");
        command.append(to_string(chan_num[i]));

        //printf("[%d] %s\n",i,command.c_str());
        system(command.c_str());
        sleep(1);
    }
}

void print_screen()
{   
    m.lock();
    for(auto iter=APMap.begin(); iter!=APMap.end(); iter++){
        printf("%-25s%-10d%-10d%-20s\n",string(iter->second.BSSID).c_str(), iter->second.pwr,iter->second.Beacons,string(iter->second.SSID).c_str());
    }
    m.unlock();
}

int main(int argc, char* argv[]) {
    if(argc !=2){
        usage();
        return -1;
    }
    param.dev_ = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);	//pcap을 여는 함수, (패킷을오픈할디바이스, 패킷최대크기, promiscuous, timeout, 에러버퍼)
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    thread* t = new thread(channel_hopping,param.dev_);
    t->detach();


    system("clear");
    printf("[BSSID]                  [pwr]     [Beacons] [ESSID]             \n");

	while (true) {
		struct pcap_pkthdr* header;	//패킷 헤더를 담는 구조체
		const u_char* packet;		//패킷 데이터를 읽어올 위치
		int res = pcap_next_ex(pcap, &header, &packet);	//pcap에서 데이터를 읽어 header에 패킷헤더를 저장하고 packet가 패킷 데이터를 가르키도록 함
		if (res == 0) continue;	//timeout
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {	//에러 발생시 예외처리
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        struct RadiotapHeader *radiotapHeader;
        struct BecaonMacHeader *macheader;
        struct BecaonBody_fixed *bodyfixed;
        char* radiotap_iter;
        char* body_iter;
        struct Airodump_values airodump_values;

        radiotapHeader = (struct RadiotapHeader *)(packet);
        if(radiotapHeader->present_flags_.dbm_antenna_sig==1){
            airodump_values.pwr = get_radiotap_PWR(radiotapHeader);
        }
        else{
            airodump_values.pwr = 0;
        }
        
        macheader = (struct BecaonMacHeader *)(packet + radiotapHeader->hd_len());
        if(ntohs(macheader->frame_control_) != macheader->type_beacon_frame){
            continue;
        }
        
        airodump_values.BSSID = macheader->BSSID;
        bodyfixed = (struct BecaonBody_fixed *)(macheader + 1);
        body_iter = (char *)(bodyfixed + 1);

        if(*body_iter==0x00){
            unsigned int tag_length = *(++body_iter);
            char *tmp = (char *)malloc((unsigned int)tag_length+1);
            strncpy(tmp,++body_iter,tag_length);
            tmp[tag_length] = '\x00'; 
            body_iter += tag_length;
            airodump_values.SSID = tmp;
            free(tmp);   
        }

        m.lock();
        auto iter = APMap.find(airodump_values.BSSID);
        if(APMap.empty() || iter==APMap.end()){
            airodump_values.Beacons = 1;
            APMap.insert({airodump_values.BSSID, airodump_values});
            iter++;
        }
        else{
            airodump_values.Beacons = iter->second.Beacons + 1;
            iter->second = airodump_values;
        }
        m.unlock();


        print_screen();
    }

	pcap_close(pcap);	

}


#pragma pack(pop)
