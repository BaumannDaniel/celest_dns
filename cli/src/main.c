#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "compass_dns.h"

#define FLAG_PREFIX '-'
#define DOMAIN_FLAG 'd'
#define SERVER_FLAG 's'
#define PORT_FLAG 'p'

typedef struct CliConfig {
    char *server;
    char *domain;
} CliConfig;

void send_dns_message() {
    const DnsHeader dns_header = {
        .id = 100, .qr = 0, .opcode = OC_QUERY,
        .aa = 0, .tc = 0, .rd = 1,
        .ra = 0, .z = 0, .rcode = 0,
        .qd_count = 1, .an_count = 0, .ns_count = 0,
        .ar_count = 0
    };
    const DnsQuestion dns_question = {
        .domain = "facebook.com",
        .q_type = TYPE_A,
        .q_class = CLASS_IN
    };
    const DnsQuestion dns_questions[1] = {dns_question};
    const DnsMessage dns_message = {
        .header = dns_header,
        .questions = dns_questions
    };
    u_int16_t dns_message_buffer_size = 0;
    const u_int8_t *dns_message_buffer = dns_message_to_buffer(&dns_message, &dns_message_buffer_size);

    const char *server_ip = "8.8.8.8";
    u_int32_t server_ip2;
    inet_pton(AF_INET, server_ip, &server_ip2);
    const struct sockaddr_in dns_server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr = {htonl(server_ip2)}
    };
    const int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == -1) {
        return;
    }
    const int reuse = 1;
    setsockopt(udp_socket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    sendto(
        udp_socket, dns_message_buffer, dns_message_buffer_size,
        0, (struct sockaddr *) &dns_server_addr, sizeof(dns_server_addr)
    );
    u_int8_t response_buffer[512] = {0};
    recvfrom(udp_socket, response_buffer, 512, 0, NULL, NULL);
    printf(response_buffer);
}

int main(const int argc, char *argv[]) {
    CliConfig cli_config = {
        .server = NULL,
        .domain = NULL
    };
    int argc_index = 0;
    while (argc_index < argc - 1) {
        const char *arg = argv[argc_index];
        if (arg[0] != FLAG_PREFIX) {
            argc_index++;
            continue;
        }
        if (arg[1] == SERVER_FLAG) {
            cli_config.server = argv[argc_index + 1];
            argc_index += 2;
            continue;
        }
        if (arg[1] == DOMAIN_FLAG) {
            cli_config.domain = argv[argc_index + 1];
            argc_index += 2;
            continue;
        }
        argc_index++;
    }
    send_dns_message();
}
