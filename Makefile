cc=g++
opt=-o pcapParser
obj=hw4.cpp
all: 
	$(cc) -I/usr/include/pcap $(obj) -lpcap $(opt)
run:
	$(CURDIR)/pcapParser
clean:
	rm pcapParser
