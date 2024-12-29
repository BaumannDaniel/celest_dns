#include <stdio.h>
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
    u_int16_t port;
    char *domain;
} CliConfig;

void send_dns_query(
    const struct sockaddr_in dns_server_addr,
    const DnsMessage *query_dns_message,
    DnsMessage *response_dns_message
) {
    u_int16_t dns_message_buffer_size = 0;
    const u_int8_t *dns_message_buffer = dns_message_to_buffer(query_dns_message, &dns_message_buffer_size);

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
    parse_dns_message(response_buffer, response_dns_message);
}

void print_dns_response(const CliConfig *cli_config, const DnsMessage *dns_message) {
    printf("Domain: %s\n", cli_config->domain);
    printf("Dns-Server: %s:%d\n", cli_config->server, cli_config->port);
    printf("IPv4-Addresses:\n");
    for (int i = 0; i < dns_message->header.an_count; i++) {
        if (dns_message->answers[i].r_type != TYPE_A) continue;
        const u_int32_t *ip_ptr = (u_int32_t*) dns_message->answers[i].r_data;
        const struct in_addr ip_addr = { .s_addr = *ip_ptr };
        char *ip_string = inet_ntoa(ip_addr);
        printf("    - %s\n", ip_string);
    }
}

int main(const int argc, char *argv[]) {
    CliConfig cli_config = {
        .server = NULL,
        .port = 53,
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
        if (arg[1] == PORT_FLAG) {
            cli_config.port = strtol(argv[argc_index + 1], NULL, 10);
            argc_index += 2;
            continue;
        }
        argc_index++;
    }
    const DnsHeader dns_header = {
        .id = 2224, .qr = 0, .opcode = OC_QUERY,
        .aa = 0, .tc = 0, .rd = 1,
        .ra = 0, .z = 0, .rcode = 0,
        .qd_count = 1, .an_count = 0, .ns_count = 0,
        .ar_count = 0
    };
    const DnsQuestion dns_question = {
        .domain = cli_config.domain,
        .q_type = TYPE_A,
        .q_class = CLASS_IN
    };
    const DnsQuestion dns_questions[1] = {dns_question};
    const DnsMessage dns_query = {
        .header = dns_header,
        .questions = dns_questions
    };
    DnsMessage dns_response;
    u_int32_t server_ip;
    inet_pton(AF_INET, cli_config.server, &server_ip);
    const struct sockaddr_in dns_server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(cli_config.port),
        .sin_addr = {server_ip }
    };
    send_dns_query(dns_server_addr, &dns_query, &dns_response);
    print_dns_response(&cli_config, &dns_response);
    free_dns_message(&dns_response);
}
