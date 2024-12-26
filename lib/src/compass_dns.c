#include <string.h>

#include "compass_dns.h"

#define STRING_END '\0'
#define DOMAIN_SEPARATOR '.'

static void parse_dns_header(const u_int8_t *buffer_ptr, DnsHeader *dns_header_ptr);

static void dns_header_to_buffer(const DnsHeader *dns_header_ptr, u_int8_t *buffer_ptr);

void parse_dns_questions(
    const u_int8_t *buffer_ptr,
    DnsQuestion *dns_questions_ptr,
    u_int16_t *questions_buffer_end_index_ptr
);

void dns_questions_to_buffer(
    const DnsQuestion *dns_questions,
    u_int16_t qd_count,
    u_int8_t *buffer_ptr,
    u_int16_t buffer_index,
    u_int16_t *questions_buffer_end_index_ptr
);

void free_dns_questions(DnsQuestion *dns_questions, u_int16_t qd_count);

void parse_dns_records(
    const u_int8_t *buffer_ptr,
    DnsRecord *dns_record_ptr,
    u_int16_t *records_buffer_end_index_ptr,
    u_int16_t buffer_index,
    u_int16_t record_count
);

void free_dns_records(DnsRecord *dns_records, u_int16_t record_count);

static u_int16_t big_endian_chars_to_short(u_int8_t most_sig_char, u_int8_t least_sig_char);

static void short_to_big_endian_chars(u_int8_t *big_endian_chars_ptr, u_int16_t value);

static u_int16_t big_endian_chars_to_u_int32(const u_int8_t *big_endian_chars_ptr);

static u_int16_t calc_domain_size(const u_int8_t *buffer_ptr, u_int16_t buffer_index);

static void retrieve_domain(
    const u_int8_t *buffer_ptr,
    u_int16_t buffer_index,
    char *domain_ptr,
    u_int16_t *domain_end_ptr
);

static u_int8_t *domain_to_label_sequence(const char *domain_ptr, u_int8_t *domain_sequence_size_ptr);

void parse_dns_message(const u_int8_t *buffer_ptr, DnsMessage *dns_message_ptr) {
    parse_dns_header(buffer_ptr, &dns_message_ptr->header);
    u_int16_t buffer_index = DNS_HEADER_SIZE;
    if (dns_message_ptr->header.qd_count > 0) {
        dns_message_ptr->questions = calloc(dns_message_ptr->header.qd_count, sizeof(DnsQuestion));
        parse_dns_questions(buffer_ptr, dns_message_ptr->questions, &buffer_index);
        buffer_index++;
    } else {
        dns_message_ptr->questions = NULL;
    }
    if (dns_message_ptr->header.an_count > 0) {
        dns_message_ptr->answers = calloc(dns_message_ptr->header.an_count, sizeof(DnsRecord));
        parse_dns_records(
            buffer_ptr,
            dns_message_ptr->answers,
            &buffer_index,
            buffer_index,
            dns_message_ptr->header.an_count
        );
        buffer_index++;
    } else {
        dns_message_ptr->answers = NULL;
    }
    if (dns_message_ptr->header.ns_count > 0) {
        dns_message_ptr->authorities = calloc(dns_message_ptr->header.ns_count, sizeof(DnsRecord));
        parse_dns_records(
            buffer_ptr,
            dns_message_ptr->authorities,
            &buffer_index,
            buffer_index,
            dns_message_ptr->header.ns_count
        );
        buffer_index++;
    } else {
        dns_message_ptr->authorities = NULL;
    }
    if (dns_message_ptr->header.ar_count > 0) {
        dns_message_ptr->additional = calloc(dns_message_ptr->header.ar_count, sizeof(DnsRecord));
        parse_dns_records(
            buffer_ptr,
            dns_message_ptr->additional,
            &buffer_index,
            buffer_index,
            dns_message_ptr->header.ar_count
        );
    } else {
        dns_message_ptr->additional = NULL;
    }
}

u_int8_t *dns_message_to_buffer(const DnsMessage *dns_message, u_int16_t *buffer_size_ptr) {
    u_int8_t *buffer_ptr = calloc(512, sizeof(char));
    dns_header_to_buffer(&dns_message->header, buffer_ptr);
    *buffer_size_ptr = DNS_HEADER_SIZE;
    return buffer_ptr;
}

void free_dns_message(DnsMessage *dns_message) {
    if (dns_message->header.qd_count > 0) {
        free_dns_questions(dns_message->questions, dns_message->header.qd_count);
        free(dns_message->questions);
        dns_message->questions = NULL;
    }
    if (dns_message->header.an_count > 0) {
        free_dns_records(dns_message->answers, dns_message->header.an_count);
        free(dns_message->answers);
        dns_message->answers = NULL;
    }
    if (dns_message->header.ns_count > 0) {
        free_dns_records(dns_message->authorities, dns_message->header.ns_count);
        free(dns_message->authorities);
        dns_message->authorities = NULL;
    }
    if (dns_message->header.ar_count > 0) {
        free_dns_records(dns_message->additional, dns_message->header.ar_count);
        free(dns_message->additional);
        dns_message->additional = NULL;
    }
}

void parse_dns_header(const u_int8_t *buffer_ptr, DnsHeader *dns_header_ptr) {
    dns_header_ptr->id = big_endian_chars_to_short(buffer_ptr[0], buffer_ptr[1]);
    dns_header_ptr->qr = (buffer_ptr[2] & QR_BYTE_MASK) >> 7;
    dns_header_ptr->opcode = (buffer_ptr[2] & OPCODE_BYTE_MASK) >> 3;
    dns_header_ptr->aa = (buffer_ptr[2] & AA_BYTE_MASK) >> 2;
    dns_header_ptr->tc = (buffer_ptr[2] & TC_BYTE_MASK) >> 1;
    dns_header_ptr->rd = buffer_ptr[2] & RD_BYTE_MASK;
    dns_header_ptr->ra = (buffer_ptr[3] & RA_BYTE_MASK) >> 7;
    dns_header_ptr->z = (buffer_ptr[3] & Z_BYTE_MASK) >> 4;
    dns_header_ptr->rcode = buffer_ptr[3] & RCODE_BYTE_MASK;
    dns_header_ptr->qd_count = big_endian_chars_to_short(buffer_ptr[4], buffer_ptr[5]);
    dns_header_ptr->an_count = big_endian_chars_to_short(buffer_ptr[6], buffer_ptr[7]);
    dns_header_ptr->ns_count = big_endian_chars_to_short(buffer_ptr[8], buffer_ptr[9]);
    dns_header_ptr->ar_count = big_endian_chars_to_short(buffer_ptr[10], buffer_ptr[11]);
}

void dns_header_to_buffer(const DnsHeader *dns_header_ptr, u_int8_t *buffer_ptr) {
    short_to_big_endian_chars(buffer_ptr, dns_header_ptr->id);
    buffer_ptr[2] = 0;
    if (dns_header_ptr->qr) buffer_ptr[2] += QR_BYTE_MASK;
    buffer_ptr[2] += dns_header_ptr->opcode << 3;
    if (dns_header_ptr->aa) buffer_ptr[2] += AA_BYTE_MASK;
    if (dns_header_ptr->tc) buffer_ptr[2] += TC_BYTE_MASK;
    if (dns_header_ptr->rd) buffer_ptr[2] += RD_BYTE_MASK;
    buffer_ptr[3] = 0;
    if (dns_header_ptr->ra) buffer_ptr[3] += RA_BYTE_MASK;
    buffer_ptr[3] += dns_header_ptr->z << 4;
    buffer_ptr[3] += dns_header_ptr->rcode;
    short_to_big_endian_chars(buffer_ptr + 4, dns_header_ptr->qd_count);
    short_to_big_endian_chars(buffer_ptr + 6, dns_header_ptr->an_count);
    short_to_big_endian_chars(buffer_ptr + 8, dns_header_ptr->ns_count);
    short_to_big_endian_chars(buffer_ptr + 10, dns_header_ptr->ar_count);
}

void parse_dns_questions(
    const u_int8_t *buffer_ptr,
    DnsQuestion *dns_questions_ptr,
    u_int16_t *questions_buffer_end_index_ptr
) {
    const u_int16_t qd_count = big_endian_chars_to_short(buffer_ptr[4], buffer_ptr[5]);
    u_int16_t buffer_index = DNS_HEADER_SIZE;
    for (u_int16_t i = 0; i < qd_count; i++) {
        dns_questions_ptr += i;
        dns_questions_ptr->domain_size = calc_domain_size(buffer_ptr, buffer_index);
        dns_questions_ptr->domain = calloc(dns_questions_ptr->domain_size, sizeof(char));
        retrieve_domain(buffer_ptr, buffer_index, dns_questions_ptr->domain, &buffer_index);
        buffer_index++;
        dns_questions_ptr->q_type = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
        dns_questions_ptr->q_class = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
    }
    *questions_buffer_end_index_ptr = buffer_index - 1;
}

void dns_questions_to_buffer(
    const DnsQuestion *dns_questions,
    const u_int16_t qd_count,
    u_int8_t *buffer_ptr,
    u_int16_t buffer_index,
    u_int16_t *questions_buffer_end_index_ptr
) {
    for (u_int16_t i = 0; i < qd_count; i++) {
        u_int8_t domain_sequence_size = 0;
        u_int8_t *domain_label_sequence = domain_to_label_sequence(dns_questions[i].domain, &domain_sequence_size);
        memcpy(buffer_ptr + buffer_index, domain_label_sequence, domain_sequence_size);
        free(domain_label_sequence);
        buffer_index *= domain_sequence_size;
        short_to_big_endian_chars(buffer_ptr + buffer_index, dns_questions->q_type);
        buffer_index += 2;
        short_to_big_endian_chars(buffer_ptr + buffer_index, dns_questions->q_type);
        buffer_index += 2;
    }
    *questions_buffer_end_index_ptr = buffer_index - 1;
}

void free_dns_questions(DnsQuestion *dns_questions, const u_int16_t qd_count) {
    for (int i = 0; i < qd_count; i++) {
        free(dns_questions[i].domain);
        dns_questions[i].domain = NULL;
    }
}

void parse_dns_records(
    const u_int8_t *buffer_ptr,
    DnsRecord *dns_record_ptr,
    u_int16_t *records_buffer_end_index_ptr,
    u_int16_t buffer_index,
    const u_int16_t record_count
) {
    for (u_int16_t i = 0; i < record_count; i++) {
        dns_record_ptr += i;
        dns_record_ptr->domain_size = calc_domain_size(buffer_ptr, buffer_index);
        dns_record_ptr->domain = calloc(dns_record_ptr->domain_size, sizeof(char));
        retrieve_domain(buffer_ptr, buffer_index, dns_record_ptr->domain, &buffer_index);
        buffer_index++;
        dns_record_ptr->r_type = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
        dns_record_ptr->r_class = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
        dns_record_ptr->ttl = big_endian_chars_to_u_int32(buffer_ptr + buffer_index);
        buffer_index += 4;
        dns_record_ptr->rd_length = big_endian_chars_to_short(buffer_ptr[buffer_index], buffer_ptr[buffer_index + 1]);
        buffer_index += 2;
        dns_record_ptr->r_data = calloc(dns_record_ptr->rd_length, sizeof(char));
        memcpy(dns_record_ptr->r_data, buffer_ptr + buffer_index, dns_record_ptr->rd_length);
        buffer_index += dns_record_ptr->rd_length;
    }
    *records_buffer_end_index_ptr = buffer_index - 1;
}

void free_dns_record(DnsRecord *dns_record) {
    free(dns_record->domain);
    dns_record->domain = NULL;
    free(dns_record->r_data);
    dns_record->r_data = NULL;
}

void free_dns_records(DnsRecord *dns_records, const u_int16_t record_count) {
    for (int i = 0; i < record_count; i++) {
        free(dns_records[i].domain);
        dns_records[i].domain = NULL;
        free(dns_records[i].r_data);
        dns_records[i].r_data= NULL;
    }
}

static u_int16_t big_endian_chars_to_short(const u_int8_t most_sig_char, const u_int8_t least_sig_char) {
    return most_sig_char * 256 + least_sig_char;
}

static void short_to_big_endian_chars(u_int8_t *big_endian_chars_ptr, const u_int16_t value) {
    big_endian_chars_ptr[1] = value % 256;
    big_endian_chars_ptr[0] = (value - big_endian_chars_ptr[1]) / 256;
}

static u_int16_t big_endian_chars_to_u_int32(const u_int8_t *big_endian_chars_ptr) {
    return big_endian_chars_ptr[0] * 16777216
           + big_endian_chars_ptr[1] * 65536
           + big_endian_chars_ptr[2] * 256
           + big_endian_chars_ptr[3];
}

static u_int16_t calc_domain_size(const u_int8_t *buffer_ptr, u_int16_t buffer_index) {
    u_int16_t domain_length = 0;
    u_int8_t segment_indicator = buffer_ptr[buffer_index];
    buffer_index++;
    while (segment_indicator > 0) {
        if (segment_indicator & QUESTION_PTR_BYTE_MASK) {
            const u_int16_t offset = big_endian_chars_to_short(
                segment_indicator & QUESTION_PTR_OFFSET_BYTE_MASK,
                buffer_ptr[buffer_index]
            );
            buffer_index = offset;
            segment_indicator = buffer_ptr[buffer_index];
            buffer_index++;
            continue;
        }
        // account for '.' separator
        if (domain_length > 0) domain_length++;
        domain_length += segment_indicator;
        buffer_index += segment_indicator;
        segment_indicator = buffer_ptr[buffer_index];
        buffer_index++;
    }
    // accounting for string end char
    return domain_length + 1;
}

static void retrieve_domain(
    const u_int8_t *buffer_ptr,
    u_int16_t buffer_index,
    char *domain_ptr,
    u_int16_t *domain_end_ptr
) {
    u_int16_t domain_index = 0;
    // caches buffer index when buffer index is set to domain pointer
    u_int16_t domain_pointer_end_index = 0;
    u_int8_t segment_indicator = buffer_ptr[buffer_index];
    buffer_index++;
    while (segment_indicator > 0) {
        if (segment_indicator & QUESTION_PTR_BYTE_MASK) {
            const u_int16_t offset = big_endian_chars_to_short(
                segment_indicator & QUESTION_PTR_OFFSET_BYTE_MASK,
                buffer_ptr[buffer_index]
            );
            domain_pointer_end_index = buffer_index + 1;
            buffer_index = offset;
            segment_indicator = buffer_ptr[buffer_index];
            buffer_index++;
            continue;
        }
        if (domain_index > 0) {
            domain_ptr[domain_index] = DOMAIN_SEPARATOR;
            domain_index++;
        }
        memcpy(domain_ptr + domain_index, buffer_ptr + buffer_index, segment_indicator);
        domain_index += segment_indicator;
        buffer_index += segment_indicator;
        segment_indicator = buffer_ptr[buffer_index];
        buffer_index++;
    }
    domain_ptr[domain_index] = STRING_END;
    if (domain_pointer_end_index > 0) buffer_index = domain_pointer_end_index;
    *domain_end_ptr = buffer_index - 1;
}

static u_int8_t *domain_to_label_sequence(const char *domain_ptr, u_int8_t *domain_sequence_size_ptr) {
    u_int8_t *label_sequence = calloc(255, sizeof(char));
    u_int8_t sequence_index = 0;
    u_int8_t domain_index = 0;
    u_int8_t label_size = 0;
    while (domain_ptr[domain_index - 1] != STRING_END) {
        if (domain_ptr[domain_index] == DOMAIN_SEPARATOR || domain_ptr[domain_index] == STRING_END) {
            label_sequence[sequence_index] = label_size;
            sequence_index++;
            memcpy(label_sequence + sequence_index, domain_ptr + (domain_index - label_size), label_size);
            sequence_index += label_size;
            domain_index++;
            label_size = 0;
            continue;
        }
        domain_index++;
        label_size++;
    }
    label_sequence[sequence_index] = 0x00;
    sequence_index++;
    *domain_sequence_size_ptr = sequence_index;
    return label_sequence;

}
