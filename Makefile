all: arp_spoof

arp_spoof : arp_spoof.o main.o
	g++ -o arp_spoof arp_spoof.o arp_spoof.o -lpcap

arp_spoof.o: arp_spoof.cpp arp_spoof.h
	g++ -c -o arp_spoof.o arp_spoof.cpp -lpcap

main.o: main.cpp arp_spoof.h
	g++ -c -o main.o main.cpp

clean:
	rm -f arp_spoof
	rm -f *.o