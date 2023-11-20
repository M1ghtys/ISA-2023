/*
ISA Project
Jakub Sychra
Academic Year 23/24

DHCP Communication Monitoring (2.)
*/

#include "proj.h"

// globals
std::vector<std::string> ip_prefixes;
std::string filename, interface;
std::string logged;
std::vector<range> addresses;
WINDOW *win;

// handles CTRL + C to exit the app and clear resources
void signal_handler(int signum) {
    if (signum == SIGINT) {
        delwin(win);
        endwin();
        std::cout << "\n\n\nInterrupt signal received. Closing application...\n";

        std::vector<range>::iterator addr;

        for (addr = addresses.begin(); addr != addresses.end(); addr++)
        {
            addr->addresses.clear();
        }
        addresses.clear();
        ip_prefixes.clear();
        _exit(0);
    }
}

// converts string ip to numeric value
uint32_t ipToNum(std::string ip){
    uint32_t  res = 0;
    std::string helpingSubstring;
    
    for(int i = 3; i >= 0; i--){
        std::string helpingSubstring;
        int slashP = ip.find('.');
        if(slashP != -1){
            helpingSubstring = ip.substr(0, slashP);
            ip = ip.substr(slashP+1);
            res += (std::stoi(helpingSubstring)<<(8*i));
        }else{
            res += std::stoi(ip);
        }
    }

    return res;
}

// prints addresses and their usage
// differs for read/interface based on existance of global screen and flag for singular print for read
void printAddresses(bool finishedFlag){
    std::vector<range>::iterator addr;
    if(win == nullptr && finishedFlag){
        std::cout << "IP-Prefix\t\tMax-hosts\tAllocated addresses\tUtilization" << std::endl;
        for (addr = addresses.begin(); addr != addresses.end(); addr++)
        {
            std::cout << addr->subnet << "\t\t" 
                    << std::dec << addr->capacity << "\t\t" 
                    << addr->allocated << "\t\t\t";
            if(addr->capacity==0){
                std::cout << std::setprecision(2) << std::fixed << "-----" << std::endl;
            }else{
                std::cout << std::setprecision(2) << std::fixed << ((float)addr->allocated/(float)addr->capacity)*100 << "%" << std::endl;
            }   
        }
    }else{
        wclear(win);
        mvwprintw(win, 0, 0, "IP-Prefix\t\tMax-hosts\tAllocated addresses\tUtilization");
        int row = 2;
        std::ostringstream formatedstr;
        for (addr = addresses.begin(); addr != addresses.end(); addr++)
        {
            formatedstr.str("");
            // using string stream -> str -> char*  for better formatting
            formatedstr << addr->subnet << "\t\t" 
                    << std::dec << addr->capacity << "\t\t" 
                    << addr->allocated << "\t\t\t";
            if(addr->capacity==0){
                formatedstr << std::setprecision(2) << std::fixed << "-----" << std::endl;
            }else{
                formatedstr << std::setprecision(2) << std::fixed << ((float)addr->allocated/(float)addr->capacity)*100 << "%" << std::endl;
            } 
            std::string str = formatedstr.str();

            mvwprintw(win, row++, 0, "%s", str.c_str());
        }
        mvwprintw(win, row+1, 0, "%s", logged.c_str());
        wrefresh(win);
    }
}

// check ip address string
void checkAddr(std::string ip){
    uint32_t compareAddr = ipToNum(ip);
    std::vector<range>::iterator addr;

    for (addr = addresses.begin(); addr != addresses.end(); addr++)
    {
        // is in range?
        if(compareAddr <= addr->to && compareAddr >= addr->from){
            // logs to syslog addr that is filled 50%> and only once
            bool logError = false;
            if(((float)addr->allocated/(float)addr->capacity)<0.5){
                logError = true;
            }
            // check if addr is present
            if(addr->addresses.find(ip) == addr->addresses.end()){
                // not found
                // add to map and increase allocated
                addr->allocated++;
                addr->addresses[ip] = true;
                
            }else{
                // if addr is in map, check if it isnt released
                if(auto element = addr->addresses.find(ip)->second == false){
                    element = true;
                    addr->allocated++;
                }
            }
            // can log and is 50% or more filled
            if(logError && (((float)addr->allocated/(float)addr->capacity)>=0.5)){
                std::string log = "Prefix " + addr->subnet + " is at least 50 %% filled";
                if(win == nullptr){
                    std::cout << log;
                }else{
                    logged.append(log + "\n");
                }
                
               
                // send syslog message with NOTICE priority
                syslog(5, "%s" ,log.c_str());
            }
        }
    }
}

// adds addresses to global structure
//                   * used to check if address fits into specified range
bool validateAndAddAddress(const std::string& cidr)
{
    // verify substr for MASK
    const long unsigned int slashP = cidr.find('/');
    if (slashP == std::string::npos) {
        return false; // no / found
    }

    std::string ip = cidr.substr(0, slashP);
    std::string mask = cidr.substr(slashP+1);

    // check if addr is valid
    struct sockaddr_in sa;
    if(!(inet_pton(AF_INET, ip.c_str(), &sa)==1)){
        return false;
    }

    int maskValue = std::stoi(mask);
    if(!(maskValue > 0 && maskValue < 32)){
        return false;
    }

    // addr is correct
    // add header
    // convert addr to numeric
    // add ranges using mask
    uint32_t addr = ipToNum(ip);
    // mask -1 because of 1UL usage
    uint32_t compareMask =  (1UL << (32-maskValue))-1;
    uint32_t  netAddr = addr & (~compareMask);
    uint32_t  addrMin = netAddr + 1;
    uint32_t  addrMax = (netAddr | compareMask) - 1;

    range newRange;
   
    newRange.subnet = cidr;
    newRange.allocated = 0;
    newRange.capacity = compareMask - 1;
    newRange.from = addrMin;
    newRange.to = addrMax;

    addresses.push_back(newRange);

    return true;
}

// parses arguments 
// usage 
// ./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]
int argumentParser(char** argv, int argc){
    int option;
    bool optR, optI = false;

    while ((option = getopt(argc, argv, "r:i:")) != -1) {
        switch (option) {
            case 'r':
                optR = true;
                filename = optarg;
                break;
            case 'i':   
                optI = true;
                interface = optarg;
                break;
            default:
                std::cerr << "./dhcp-stats [-r <filename>] [-i <interface-name>] <ip-prefix> [ <ip-prefix> [ ... ] ]" << std::endl;
                _exit(1);
        }
    }

    //  -r & -i check
    if (optR && optI) {
        std::cerr << "Error: -r and -i cant be used at the same time" << std::endl;
        _exit(1);
    }

    // no argument check
    if (!optR && !optI) {
        std::cerr << "Error: Plase specify either -r or -i parameter" << std::endl;
        _exit(1);
    }

    // ip processing
    for (int i = optind; i < argc; i++) {
        ip_prefixes.push_back(argv[i]);
    }

    if (ip_prefixes.empty()) {
        std::cerr << "Error: No IP prefixes specified" << std::endl;
        _exit(1);
    }

    for (const std::string& ip_prefix : ip_prefixes) {
        if(!validateAndAddAddress(ip_prefix))
        {
            std::cerr << "Error: Incorrect IP addr" << std::endl;
            _exit(1);
        }
    }

    return optR ? 2 : 1; 
}

// function called by pcap_loop
void packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {    
    const struct ether_header* ethernet_header = (struct ether_header*)packet;

    // Determine the Ethernet frame type
    uint16_t frame_type = ntohs(ethernet_header->ether_type);

    if (frame_type == ETHERTYPE_IP) {
        const struct ip* ip_header = (struct ip*)(packet + ETHER_HDR_LEN);

        uint8_t ip_protocol = ip_header->ip_p;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        if (ip_protocol == IPPROTO_UDP) {
            // Handle UDP packets
            const struct udphdr* udp_header = (struct udphdr*)(packet + ETHER_HDR_LEN + ip_header->ip_hl * 4);

            // Determine the source and destination ports
            uint16_t src_port = ntohs(udp_header->uh_sport);

            if (src_port == 67) {
                // define dhcp payload position 
                const u_char* dhcp_payload = packet + ETHER_HDR_LEN + ip_header->ip_hl * 4 + sizeof(struct udphdr);
                DhcpPacket dhcp_packet;
                // load the payload into dhcp structure
                memcpy(&dhcp_packet, dhcp_payload, sizeof(DhcpPacket));
                // Checks first four octets for magic cookie
                if(dhcp_packet.options[0] != 99 || dhcp_packet.options[1] != 130 || dhcp_packet.options[2] != 83 || dhcp_packet.options[3]!=99){
                    // Print for debug purpose, otherwise end the processing
                    //std::cout << "Wrong cookie " << std::endl;
                    return;
                } 

                // position after magic cookie
                int position = 4;

                // iterate through options because they are not ordered to find dhcp message
                while(1){
                    if((int)dhcp_packet.options[position] == 53){
                        break;
                    }else if((int)dhcp_packet.options[position] == 0){
                        // padding has no length byte
                        position++;
                        continue;
                    }else if((int)dhcp_packet.options[position] == 255 || position >= 312){
                        // 255 -> end of options
                        // position >= 312 is limit of the structure, this check prevents segfault
                        return;
                    }
                    int pos = (int)dhcp_packet.options[++position] + 1;

                    position += pos;
                }
                
                if((int)dhcp_packet.options[position] == 53 && (int)dhcp_packet.options[position+1] == 1){
                    switch ((int)dhcp_packet.options[position+2])
                    {
                    case 5:
                        // DHCP ACK
                        // ack can also be a response to DHCP inform
                        // code 53
                        // len 4
                        // address 8b 8b 8b 8b 

                        char client_ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &dhcp_packet.yiaddr, client_ip_str, INET_ADDRSTRLEN);

                        if(dhcp_packet.yiaddr != 0){
                            checkAddr(client_ip_str);
                        }
                        printAddresses();
                        break;
                    default:
                        // not ack, ignore
                        break;
                    }
                }
            }
        }
    } 
    /*else {
        std::cout << "Unknown Packet Type (EtherType: 0x" << std::hex << frame_type << std::dec << ")" << std::endl;
    }*/
    return;
}

int main(int argc, char** argv){
    // parse the arguments
    int option = argumentParser(argv, argc);
    // monitor CTRL + C for screen exit
    signal(SIGINT, signal_handler);
    // get number of rows to be used in screen from address count
    int rows = 0;
    rows = addresses.size() + 2;

    char errbuf[PCAP_ERRBUF_SIZE];
    // interface
    if(option == 1){
        pcap_if_t *interfaces,*temp;
        pcap_if_t *monitoredInterface;

        if(pcap_findalldevs(&interfaces,errbuf)==-1)
        {
            printf("\nerror in pcap findall devs");
            return -1;   
        }

        // go through list of available devices
        for(temp=interfaces;temp;temp=temp->next)
        {
            if(temp->name == interface){
                monitoredInterface = temp;
                break;
            }
        }

        // interface is null
        if(monitoredInterface == nullptr){
            std::cerr << "Error: Specified interface does not exist" << std::endl;
            _exit(1);
        }

        // interface exists and all arguments are correct 
        // obtain packet capture handle 
        pcap_t *descr = NULL;
        descr = pcap_open_live(temp->name, 2048, 1, 1024, errbuf);

        if(descr == NULL){
            std::cerr << errbuf << std::endl;
            _exit(1);
        }

        struct bpf_program filter;

        if(pcap_compile(descr, &filter, "udp port 67", 0, PCAP_NETMASK_UNKNOWN)== -1){
            std::cerr << "Error: pcap compile error" << std::endl;
            _exit(1);
        }
        if(pcap_setfilter(descr,&filter)==-1){
            std::cerr << "Error: set filter error" << std::endl;
            _exit(1);
        }
        
        // init global window with width 100
        initscr();
        win = newwin(rows*2,100,0,0);
        // prints first set of addresses so text is available before receiving first packet
        printAddresses();

        // infinite capture loop, terminated by sigint
        pcap_loop(descr, -1, packet_handler, nullptr);
        // this part shouldnt be reachable, but for clarity and consistency code acts as if it is
        delwin(win);
        endwin();
        pcap_close(descr);

        _exit(0);
    }
    // Read File
    if(option == 2){
        pcap_t* pcap = pcap_open_offline(filename.c_str(), errbuf);
        if (pcap == nullptr) {
            std::cerr << "Error: Cant't open PCAP file: " << errbuf << std::endl;
            _exit(1);
        }
        
        // Start packet processing loop
        pcap_loop(pcap, -1, packet_handler, nullptr);
        
        // Close the PCAP file
        pcap_close(pcap);
    }

    // Add spacing
    std::cout << std::endl << std::endl;
    // Prints addresses at the end, reachable only from file read
    printAddresses(true);
    
    std::vector<range>::iterator addr;

    for (addr = addresses.begin(); addr != addresses.end(); addr++)
    {
        addr->addresses.clear();
    }
    addresses.clear();
    ip_prefixes.clear();

    _exit(0);
}