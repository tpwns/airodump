LDLIBS=-lpcap -lpthread

all: airodump

airodump: main.o mac.o beaconframe.o radiotap.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o