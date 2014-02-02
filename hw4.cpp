#include <iostream>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
 
using namespace std;
 
void packetHandler( const struct pcap_pkthdr* pkthdr, const u_char* packet);
int offLineCapture( char *pcapName );
int onLineCapture( char *devName );
void signalHandler( int sig );
int addToTable( char src, char srcPort, char dest, char destPort, int pSize );

bool liveCapture;

 
struct connect {
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort;
	u_int destPort;
	float totalBytes;
	int howManyPacks;

};				/* ----------  end of struct connect  ---------- */

typedef struct connect Connect;

Connect contTable[200];
int upper = 0;

int main( int argc, char *argv[]) {
	int c; 


	signal(SIGINT, signalHandler);
	liveCapture = true;
	c = getopt(argc, argv, "ir:");

	switch ( c ) {
			case 'i':	
					onLineCapture(argv[2]);
					break;

			case 'r':	
					offLineCapture(argv[2]);
					break;

			default:	
					break;
	}				/* -----  end switch  ----- */

	// start packet processing loop, just like live capture
/* 	if ( pcap_dispatch(descr, 0, packetHandler, NULL) < 0) {
 * 		cout << "pcap_loop() failed: " << pcap_geterr(descr);
 * 		return 1;
 * 	}
 * 	cout << "capture finished" << endl;
 */
 
	return 0;
}
 
void signalHandler( int sig ) {
		liveCapture = false;
}

int onLineCapture( char *devName ) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr hdr;
	const u_char *packet;
	int packCount = 0, i = 0;

	handle = pcap_open_live(devName, 4096, 1, 0, errbuf);
	if ( NULL == handle ) {
			cout << "Couldn't find default device: " << errbuf << endl;
			return 0;
	}

	cout  <<"sourceIp" << ":" << "sourcePort" << " -> " << "destIp" << ":" << "destPort" << "\t" << "dataLength"<< endl;
	do {
			packet = pcap_next(handle, &hdr);
			if ( NULL == packet ) {
					return 1;
			}
			packCount++;
			packetHandler( &hdr, packet );

	} while( liveCapture );

	cout << endl << "online-caputre is fin" << endl;
	cout << packCount << " packets captured " << endl;

	cout << "has " << upper << "connect" << endl;
	cout << "connetion\t" << "\t\t\t\t\tpackets\t" << "bytes\t" << "B/p" <<endl;
	for ( i = 0; i < upper; i++ ) {
			cout << contTable[i].sourceIp << ":" << contTable[i].sourcePort << "\t->\t" << contTable[i].destIp << ":" << contTable[i].destPort
					<< "\t" <<contTable[i].howManyPacks << "\t" << contTable[i].totalBytes << "\t" 
						<< contTable[i].totalBytes / contTable[i].howManyPacks << endl;

	}

	return 1;
}
int offLineCapture( char *pcapName ) {
	pcap_t *descr;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr hdr;
	const u_char *packet;
	int packCount = 0, i = 0;

	// open capture file for offline processing
	descr = pcap_open_offline(pcapName, errbuf);
	if (descr == NULL) {
		cout << "pcap_open_offline() failed: " << errbuf << endl;
		return 1;
	}
 
	cout  <<"sourceIp" << ":" << "sourcePort" << " -> " << "destIp" << ":" << "destPort" << "\t" << "dataLength"<< endl;
	do {
			packet = pcap_next(descr, &hdr);
			if ( NULL == packet ) {
					cout << packCount << " packets captured " << endl;
					break;
			}
			packCount++;
			packetHandler( &hdr, packet );
	} while(1);

	cout << "has " << upper << "connect" << endl;
	cout << "connetion\t" << "\t\t\t\t\tpackets\t" << "bytes\t" << "B/p" <<endl;
	for ( i = 0; i < upper; i++ ) {
			cout << contTable[i].sourceIp << ":" << contTable[i].sourcePort << "\t->\t" << contTable[i].destIp << ":" << contTable[i].destPort
					<< "\t" <<contTable[i].howManyPacks << "\t" << contTable[i].totalBytes << "\t" 
						<< contTable[i].totalBytes / contTable[i].howManyPacks << endl;

	}
	return 1;

}

int addToTable( char *src, u_int srcPort, char *dest, u_int destPort, int pSize ) {
		int i = 0;
		for ( i = 0; i < upper; i++ ) {

				if ( !strcmp(contTable[i].sourceIp, src) && !strcmp(contTable[i].destIp, dest)
								&& srcPort== contTable[i].sourcePort && destPort == contTable[i].destPort ) {
						contTable[i].totalBytes += pSize;
						contTable[i].howManyPacks++;
						return 1;
				}
				if ( !strcmp(contTable[i].sourceIp, dest) && !strcmp(contTable[i].destIp, src)
								&& destPort == contTable[i].sourcePort && srcPort == contTable[i].destPort ) {
						contTable[i].totalBytes += pSize;
						contTable[i].howManyPacks++;
						return 1;
				}
		}
		strcpy( contTable[upper].sourceIp, src );	
		strcpy( contTable[upper].destIp, dest );	
		contTable[upper].sourcePort = srcPort;
		contTable[upper].destPort = destPort;
		contTable[upper].totalBytes = pSize;
		upper++;
		contTable[i].howManyPacks = 1;
		return 1;

}

void packetHandler( const struct pcap_pkthdr* pkthdr, const u_char* packet) {
	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
	u_char *data;
	int dataLength = 0, packetLength;
	string dataStr = "";
	int id = 0;
	int offset = 0;
 
	ethernetHeader = (struct ether_header*)packet;
	if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
		ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);
		id = ntohs(ipHeader->ip_id);
		offset = ntohs(ipHeader->ip_off);
 
		if (ipHeader->ip_p == IPPROTO_TCP) {
			tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
			sourcePort = ntohs(tcpHeader->source);
			destPort = ntohs(tcpHeader->dest);
			data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
			packetLength = pkthdr->len;
//			dataLength = packetLength - (sizeof(struct ether_header) + sizeof(struct ip) + 4*(tcpHeader->doff) ); /* tcp header len will change */
 			dataLength = ntohs(ipHeader->ip_len) - sizeof( struct ip ) - 4*(tcpHeader->doff); /* tcp header & ip header length will change */
			// print the results
			cout  <<sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << "\t" <<  dataLength << endl;

			addToTable( sourceIp, sourcePort, destIp, destPort, dataLength );
		}
	}
}
