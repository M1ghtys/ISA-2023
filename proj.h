/*
ISA Project
Jakub Sychra
Academic Year 23/24

DHCP Communication Monitoring (2.)
*/

#include <getopt.h>
#include <unistd.h>
#include <ncurses.h>
#include <vector>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <syslog.h>
#include <cstdlib>
#include <pcap/pcap.h>
#include <arpa/inet.h> 
#include <cstring>
#include <map>
#include <iomanip>
#include <csignal>
#include <syslog.h>

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
+---------------+---------------+---------------+---------------+
|                            xid (4)                            |
+-------------------------------+-------------------------------+
|           secs (2)            |           flags (2)           |
+-------------------------------+-------------------------------+
|                          ciaddr  (4)                          |
+---------------------------------------------------------------+
|                          yiaddr  (4)                          |
+---------------------------------------------------------------+
|                          siaddr  (4)                          |
+---------------------------------------------------------------+
|                          giaddr  (4)                          |
+---------------------------------------------------------------+
|                                                               |
|                          chaddr  (16)                         |
|                                                               |
|                                                               |
+---------------------------------------------------------------+
|                                                               |
|                          sname   (64)                         |
+---------------------------------------------------------------+
|                                                               |
|                          file    (128)                        |
+---------------------------------------------------------------+
|                                                               |
|                          options (variable)                   |
+---------------------------------------------------------------+   */
struct DhcpPacket {
    uint8_t op;           // op code
    uint8_t htype;        // hw address type
    uint8_t hlen;         // hw address length
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    char sname[64];
    char file[128];
    uint8_t options[312]; // options, limit set to 312 octets
};

typedef struct stRange
{
  std::string subnet; // for printing
  std::map<std::string, bool> addresses; // map where key is IP and bool indicates if addr is assigned 
  uint32_t from;
  uint32_t to;
  int capacity;
  int allocated;
} range;

void signal_handler(int);
uint32_t ipToNum(std::string);
void checkAddr(std::string);
bool validateAndAddAddress(const std::string&);
void printAddresses(bool finishedFlag = false);
int argumentParser(char**, int);
int main(int, char**);
void packet_handler(u_char*, const struct pcap_pkthdr*, const u_char*);
