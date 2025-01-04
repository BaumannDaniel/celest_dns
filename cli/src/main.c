#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <stdlib.h>

#include "celest_dns.h"

#define FLAG_PREFIX '-'
#define DOMAIN_FLAG 'd'
#define SERVER_FLAG 's'
#define PORT_FLAG 'p'

#define REQUEST_TIMEOUT 5000
#define DEFAULT_PORT 53

static const int16_t POLL_EVENTS_BYTE_MASK = POLLIN | POLLPRI;
static const int16_t POLL_ERROR_BYTE_MASK = POLLPRI | POLLERR | POLLNVAL;
static const DnsHeader dns_header_template = {
    .id = 0, .qr = 0, .opcode = OC_QUERY,
    .aa = 0, .tc = 0, .rd = 1,
    .ra = 0, .z = 0, .rcode = 0,
    .qd_count = 1, .an_count = 0, .ns_count = 0,
    .ar_count = 0
};

typedef struct CliConfig {
    char *server;
    uint16_t port;
    char *domain;
} CliConfig;

int send_dns_query(
    const struct sockaddr_in *dns_server_addr,
    const DnsMessage *query_dns_message,
    DnsMessage *response_dns_message
) {
    uint16_t dns_message_buffer_size = 0;
    const uint8_t *dns_message_buffer = dns_message_to_buffer(query_dns_message, &dns_message_buffer_size);
    if (dns_message_buffer == NULL) {
        return -1;
    }
    const int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        printf("Failed to create udp socket!\n");
        return -1;
    }

    if (
        sendto(
            udp_socket, dns_message_buffer, dns_message_buffer_size,
            0, (struct sockaddr *) dns_server_addr, sizeof(*dns_server_addr)
        ) < 0
    ) {
        close(udp_socket);
        printf("Failed to send dns query!\n");
        return -1;
    }
    struct pollfd poll_fd;
    poll_fd.fd = udp_socket;
    poll_fd.events = POLL_EVENTS_BYTE_MASK;
    poll(&poll_fd, 1, REQUEST_TIMEOUT);
    if (poll_fd.revents & POLL_ERROR_BYTE_MASK) {
        printf("Socket failure while awaiting response!\n");
        close(udp_socket);
        return -1;
    }
    if (poll_fd.revents & POLL_EVENTS_BYTE_MASK) {
        uint8_t response_buffer[MAX_DNS_MESSAGE_SIZE] = {0};
        const ssize_t n_read_bytes = recvfrom(udp_socket, response_buffer, MAX_DNS_MESSAGE_SIZE, 0, NULL, NULL);
        if (n_read_bytes < DNS_HEADER_SIZE) {
            printf("Failed reading response from socket!\n");
            close(udp_socket);
            return -1;
        }
        close(udp_socket);
        const int parse_result = parse_dns_message(response_buffer, response_dns_message);
        if (parse_result < 0) {
            printf("Failed to parse returned dns message!\n");
        }
        return parse_result;
    }
    printf("Dns Query timed out!\n");
    close(udp_socket);
    return -1;
}

void print_dns_response(
    const CliConfig *cli_config,
    const DnsMessage *dns_message_ipv4,
    const DnsMessage *dns_message_ipv6
) {
    printf("Domain: %s\n", cli_config->domain);
    printf("Dns-Server: %s:%d\n", cli_config->server, cli_config->port);
    printf("IPv4-Addresses:\n");
    for (int i = 0; i < dns_message_ipv4->header.an_count; i++) {
        if (dns_message_ipv4->answers[i].r_type != TYPE_A) continue;
        char ip_string[16] = {0};
        inet_ntop(AF_INET, dns_message_ipv4->answers[i].r_data, ip_string, 40);
        printf("    - %s\n", ip_string);
    }
    printf("IPv6-Addresses:\n");
    for (int i = 0; i < dns_message_ipv6->header.an_count; i++) {
        if (dns_message_ipv6->answers[i].r_type != TYPE_AAAA) continue;
        char ip_string[40] = {0};
        inet_ntop(AF_INET6, dns_message_ipv6->answers[i].r_data, ip_string, 40);
        printf("    - %s\n", ip_string);
    }
}

void parse_cli_arguments(const int argc, char *argv[], CliConfig *cli_config) {
    int argc_index = 0;
    while (argc_index < argc - 1) {
        const char *arg = argv[argc_index];
        if (arg[0] != FLAG_PREFIX) {
            argc_index++;
            continue;
        }
        switch (arg[1]) {
            case SERVER_FLAG:
                cli_config->server = argv[argc_index + 1];
                argc_index += 2;
                break;
            case DOMAIN_FLAG:
                cli_config->domain = argv[argc_index + 1];
                argc_index += 2;
                break;
            case PORT_FLAG:
                cli_config->port = strtol(argv[argc_index + 1], NULL, 10);
                argc_index += 2;
                break;
            default:
                argc_index++;
        }
    }
}

int main(const int argc, char *argv[]) {
    CliConfig cli_config = {
        .server = NULL,
        .port = 53,
        .domain = NULL
    };
    parse_cli_arguments(argc, argv, &cli_config);
    DnsHeader dns_header = dns_header_template;
    dns_header.id = time(NULL) % INT16_MAX;
    const DnsQuestion dns_question_ipv4 = {
        .domain = cli_config.domain,
        .q_type = TYPE_A,
        .q_class = CLASS_IN
    };
    const DnsQuestion dns_questions_ipv4[1] = {dns_question_ipv4};
    const DnsQuestion dns_question_ipv6 = {
        .domain = cli_config.domain,
        .q_type = TYPE_AAAA,
        .q_class = CLASS_IN
    };
    const DnsQuestion dns_questions_ipv6[1] = {dns_question_ipv6};
    const DnsMessage dns_query_ipv4 = {
        .header = dns_header,
        .questions = dns_questions_ipv4
    };
    const DnsMessage dns_query_ipv6 = {
        .header = dns_header,
        .questions = dns_questions_ipv6
    };
    DnsMessage dns_response_ipv4;
    DnsMessage dns_response_ipv6;
    uint32_t server_ip;
    if (inet_pton(AF_INET, cli_config.server, &server_ip) != 1) {
        printf("Invalid server ip!");
        return -1;
    }
    const struct sockaddr_in dns_server_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(cli_config.port),
        .sin_addr = {server_ip}
    };
    if (send_dns_query(&dns_server_addr, &dns_query_ipv4, &dns_response_ipv4) < 0) return -1;
    if (send_dns_query(&dns_server_addr, &dns_query_ipv6, &dns_response_ipv6) < 0) return -1;
    print_dns_response(&cli_config, &dns_response_ipv4, &dns_response_ipv6);
    free_dns_message(&dns_response_ipv4);
    free_dns_message(&dns_response_ipv6);
    return 0;
}
