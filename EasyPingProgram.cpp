#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <iostream>
#include <fstream>
using namespace std;

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64

// Automatic port number
#define PORT_NO 0

// Automatic port number
#define PING_SLEEP_RATE 1000000

// Gives the timeout delay for receiving packets
// in seconds
#define RECV_TIMEOUT 1

#define RUN_DEFAULT 0

#define RUN_MASS_COUNT 1

#define RUN_TIME_COUNT 2

// Define the Ping Loop
int pingloop=1;

// ping packet structure
struct ping_pkt
{
    struct icmphdr hdr;//type,id,check sum
    char msg[PING_PKT_S-sizeof(struct icmphdr)];
};

// Calculating the Check Sum
unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short*)b;
    unsigned int sum=0;
    unsigned short result;

    for ( sum = 0; len > 1; len -= 2 )
        sum += *buf++;
    if ( len == 1 )
        sum += *(unsigned char*)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

// Interrupt handler
void intHandler(int dummy)
{
    pingloop=0;
}

// Performs a DNS lookup
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
    printf("\nResolving DNS..\n");
    struct hostent *host_entity;
    char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
    int i;

    if ((host_entity = gethostbyname(addr_host)) == NULL)
    {
        // No ip found for hostname
        return NULL;
    }

    //filling up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr));

    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons (PORT_NO);
    (*addr_con).sin_addr.s_addr  = *(long*)host_entity->h_addr;

    return ip;
}

// make a ping request
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_ip, char *rev_host,int type,int massCountx,int timexx)
{
    int massCount=-1,timex=-1;
    if(type == 1)
    {
        massCount = massCountx;
    }
    if(type == 2)
    {
        timex = timexx;
    }

    int ttl_val=64, msg_count=0, i, addr_len, flag=1,  msg_received_count=0;

    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec=0, total_msec=0;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);
    // set socket options at ip to TTL and value to 64,
    // change to what you want by setting ttl_val
    if (setsockopt(ping_sockfd, SOL_IP, IP_TTL,   &ttl_val, sizeof(ttl_val)) != 0)
    {
        printf("\nSetting socket options  to TTL failed!\n");
        return;
    }
    else
    {
        printf("\nSocket set to TTL..\n");
    }

    // setting timeout of recv setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);

    // send icmp packet in an infinite loop
    while(pingloop && massCount != 0)
    {
        // flag is whether packet was sent or not
        flag=1;

        //filling packet
        bzero(&pckt, sizeof(pckt));

        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = getpid();

        for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
            pckt.msg[i] = i+'0';

        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        usleep(PING_SLEEP_RATE);

        //send packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*) ping_addr,sizeof(*ping_addr)) <= 0)
        {
            printf("\nPacket Sending Failed!\n");
            flag=0;
        }

        //receive packet
        addr_len=sizeof(r_addr);

        if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)&r_addr, (socklen_t*)&addr_len) <= 0  && msg_count>1)
        {
            printf("\nPacket receive failed!\n");
        }
          else
        {
            clock_gettime(CLOCK_MONOTONIC, &time_end);

            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec))/1000000.0 ;
            rtt_msec = (time_end.tv_sec- time_start.tv_sec) * 1000.0 + timeElapsed;


            if(flag)
            {
                if(!(pckt.hdr.type ==69 ))
                {
                    printf("Error..Packet received with ICMP type %d code %d\n",  pckt.hdr.type, pckt.hdr.code);
                }
                else
                {
                    printf("%d bytes from %s icmp_seq=%d ttl=%d  time = %Lf ms.\n",  PING_PKT_S,  ping_ip, msg_count, ttl_val, rtt_msec);
                    msg_received_count++;
                }
            }
        }
        if(massCount != -1)
        massCount--;
        clock_gettime(CLOCK_MONOTONIC, &tfe);
        double timeElapsed = ((double)(tfe.tv_nsec -   tfs.tv_nsec))/1000000.0;

        total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0+  timeElapsed ;
        if(timex !=-1 && total_msec >= timex)break;
    }
    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec -   tfs.tv_nsec))/1000000.0;

    total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0+  timeElapsed ;

    printf("\n===%s ping statistics===\n", ping_ip);
    printf("\n%d packets sent, %d packets received, %f percent  packet loss. Total time: %Lf ms.\n\n", msg_count, msg_received_count, ((msg_count - msg_received_count)/msg_count) * 100.0,  total_msec);
}

int rundata(int type,char* hostnameOrIpv4,int massCount,int timex)
{
    int sockfd;
    char *ip_addr;
    struct sockaddr_in addr_con;

    ip_addr = dns_lookup(hostnameOrIpv4, &addr_con);
    if(ip_addr==NULL)
    {
        printf("\nCould  not resolve hostname to IP address\n");
        return 0;
    }

    printf("\nTrying to connect to '%s' IP: %s\n", hostnameOrIpv4, ip_addr);

    //socket()
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // bang 3 vi day la raw socket ???
    //cout<<AF_INET << " " << SOCK_RAW <<" " <<IPPROTO_ICMP<<endl;
    if(sockfd<0)
    {
        printf("\nSocket file descriptor not received!!\n");
        return 0;
    }
    else
        printf("\nSocket file descriptor %d received\n", sockfd);

    signal(SIGINT, intHandler);//catching interrupt

    //send pings continuously
    send_ping(sockfd, &addr_con,   ip_addr, hostnameOrIpv4,type,massCount,timex);
}

int main(int argc, char *argv[])
{
    if(argc == 1)
    {
        cout<<"input wrong: please input follow format"<<endl;
        return 0;
    }

    int massCount=-1,timex=-1;
    if((argv[1][0]-'0') ==0)
    {
        if(argc == 2)
        {
            cout<<"input wrong: must input hostname or ipv4 address"<<endl;
            return 0;
        }

        if(argc == 3)
        {
            cout<<"input wrong: must input run type is 0, 1 or 2 "<<endl;
            return 0;
        }
        int type = argv[3][0]-'0';
        switch(type)
        {
            case RUN_DEFAULT:
                break;
            case RUN_MASS_COUNT:
                if(argc == 4)
                {
                    cout<<"input wrong: must input message count "<<endl;
                    return 0;
                }
                massCount= atoi(argv[4]);
                break;
            case RUN_TIME_COUNT:
                if(argc == 4)
                {
                    cout<<"input wrong: must input time to run "<<endl;
                    return 0;
                }
                timex =atoi(argv[4]);
                break;
            default:
                cout<<"input wrong: choice run type is 0, 1 or 2 for 3rd parameter"<<endl;
                return 0;
        }
        rundata(type,argv[2],massCount,timex);
    }
     else if((argv[1][0]-'0') ==1)
    {
        massCount=-1,timex=-1;

        if(argc == 2)
        {
        cout<<"input wrong: need to input unittest file address"<<endl;
        return 0;
        }
        fstream f;
        f.open(argv[2], ios::in);

        string data;
        getline(f, data);
        int testcase = stoi(data);
        for(int i = 0;i<testcase;i++)
        {
            getline(f, data);
            int type = stoi(data);
            //cout<<type<<endl;
            getline(f, data);
            string hn = data;
            char * hostname = &hn[0];
            //cout<<hostname<<endl;
            switch(type)
            {
            case RUN_DEFAULT:
                break;
            case RUN_MASS_COUNT:
                getline(f, data);
                massCount= stoi(data);
                cout<<"Testcase"<< i+1 << ": send " << massCount <<" messages to " << hostname <<endl;
                break;
            case RUN_TIME_COUNT:
                getline(f, data);
                timex =stoi(data);
                cout<<"Testcase"<< i+1 << ": send in " << timex <<" milliseconds to " << hostname <<endl;
                break;
            default:
                cout<<"input wrong"<<endl;
                return 0;
            }

            rundata(type,hostname,massCount,timex);

        }

        f.close();
    }
    else
    {
        cout<<"input wrong: choice type is 0, 1 for first parameter"<<endl;
        return 1;
    }

    return 0;
}




