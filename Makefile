all : pcap_test

pcap_test : main.o
	g++ -g -std=c++14 -o pcap_test main.o -lpcap

main.o : psy_header.h
	g++ -g -c -std=c++14 -o main.o main.cpp

clean:
	rm -f *.o pcap_test

