#include "unity.h"
#include "celest_dns.h"

#include <string.h>

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void parse_dns_header__successfully() {
    const u_int8_t dns_header_bytes[12] = {
        0x01, 0x01, 0x8f, 0xb3, 0x01, 0x02,
        0x01, 0x03, 0x01, 0x04, 0x01, 0x05
    };
    DnsHeader dns_header;
    parse_dns_header(dns_header_bytes, &dns_header);
    TEST_ASSERT_EQUAL(257, dns_header.id);
    TEST_ASSERT_EQUAL(1, dns_header.qr);
    TEST_ASSERT_EQUAL(1, dns_header.opcode);
    TEST_ASSERT_EQUAL(1, dns_header.aa);
    TEST_ASSERT_EQUAL(1, dns_header.tc);
    TEST_ASSERT_EQUAL(1, dns_header.rd);
    TEST_ASSERT_EQUAL(1, dns_header.ra);
    TEST_ASSERT_EQUAL(3, dns_header.z);
    TEST_ASSERT_EQUAL(3, dns_header.rcode);
    TEST_ASSERT_EQUAL(258, dns_header.qd_count);
    TEST_ASSERT_EQUAL(259, dns_header.an_count);
    TEST_ASSERT_EQUAL(260, dns_header.ns_count);
    TEST_ASSERT_EQUAL(261, dns_header.ar_count);
}

void parse_dns_message__parse_header_successfully() {
    const u_int8_t dns_header_bytes[12] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    DnsMessage dns_message;
    parse_dns_message(dns_header_bytes, &dns_message);
    TEST_ASSERT_EQUAL(5, dns_message.header.id);
    TEST_ASSERT_EQUAL(1, dns_message.header.qr);
    TEST_ASSERT_EQUAL(1, dns_message.header.opcode);
    TEST_ASSERT_EQUAL(1, dns_message.header.aa);
    TEST_ASSERT_EQUAL(1, dns_message.header.tc);
    TEST_ASSERT_EQUAL(1, dns_message.header.rd);
    TEST_ASSERT_EQUAL(1, dns_message.header.ra);
    TEST_ASSERT_EQUAL(3, dns_message.header.z);
    TEST_ASSERT_EQUAL(3, dns_message.header.rcode);
    TEST_ASSERT_EQUAL(0, dns_message.header.qd_count);
    TEST_ASSERT_EQUAL(0, dns_message.header.an_count);
    TEST_ASSERT_EQUAL(0, dns_message.header.ns_count);
    TEST_ASSERT_EQUAL(0, dns_message.header.ar_count);
    free_dns_message(&dns_message);
}

void parse_dns_message__parse_single_question() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    DnsMessage dns_message;
    parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message.questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message.questions[0].q_class);
    free_dns_message(&dns_message);
}

void parse_dns_message__parse_multiple_questions() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00,
        0x01, 0x03, 'w', 'w', 'w', 0x02,
        'a', 'b', 0x02, 'e', 'n', 0x00,
        0x00, 0x05, 0x00, 0x02
    };
    DnsMessage dns_message;
    parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message.questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message.questions[0].q_class);
    TEST_ASSERT_EQUAL_STRING("www.ab.en", dns_message.questions[1].domain);
    TEST_ASSERT_EQUAL(TYPE_CNAME, dns_message.questions[1].q_type);
    TEST_ASSERT_EQUAL(CLASS_CS, dns_message.questions[1].q_class);
    free_dns_message(&dns_message);
}

void parse_dns_message__parse_questions_with_pointer() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
        0x00, 0x02
    };
    DnsMessage dns_message;
    parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message.questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message.questions[0].q_class);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.questions[1].domain);
    TEST_ASSERT_EQUAL(TYPE_CNAME, dns_message.questions[1].q_type);
    TEST_ASSERT_EQUAL(CLASS_CS, dns_message.questions[1].q_class);
    free_dns_message(&dns_message);
}

void parse_dns_message__parse_questions_with_end_pointer() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0x03, 'w', 'w', 'w',
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x02
    };
    DnsMessage dns_message;
    parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message.questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message.questions[0].q_class);
    TEST_ASSERT_EQUAL_STRING("www.test.com", dns_message.questions[1].domain);
    TEST_ASSERT_EQUAL(TYPE_CNAME, dns_message.questions[1].q_type);
    TEST_ASSERT_EQUAL(CLASS_CS, dns_message.questions[1].q_class);
    free_dns_message(&dns_message);
}

void parse_dns_message__question_exceeds_max_domain_size() {
    const u_int8_t dns_header_bytes[12] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    u_int8_t dns_message_buffer[274];
    memcpy(dns_message_buffer, dns_header_bytes, 12);
    u_int16_t dns_message_buffer_index = 12;
    for (int i = 0; i < 4; i++) {
        dns_message_buffer[dns_message_buffer_index] = 62;
        dns_message_buffer_index++;
        memset(dns_message_buffer + dns_message_buffer_index, 'x', 62);
        dns_message_buffer_index += 62;
    }
    const u_int8_t dns_question_part_2[8] = {
        0x02, 'd', 'e', 0x00, 0x00,
        0x01, 0x00, 0x01
    };
    memcpy(dns_message_buffer + dns_message_buffer_index, dns_question_part_2, 8);
    DnsMessage dns_message;
    const int parse_result = parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL(-1, parse_result);
    TEST_ASSERT_NULL(dns_message.questions);
}

void parse_dns_message__parse_single_answer() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
        0x00, 0x04, 0x01, 0x02, 0x03, 0x04
    };
    DnsMessage dns_message;
    parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.answers[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message.answers[0].r_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message.answers[0].r_class);
    TEST_ASSERT_EQUAL(257, dns_message.answers[0].ttl);
    TEST_ASSERT_EQUAL(4, dns_message.answers[0].rd_length);
    const u_int8_t expected_r_data[4] = {0x01, 0x02, 0x03, 0x04};
    TEST_ASSERT_EQUAL_CHAR_ARRAY(expected_r_data, dns_message.answers[0].r_data, 4);
    free_dns_message(&dns_message);
}

void dns_message_to_buffer__convert_header_successfully() {
    const DnsHeader dns_header = {
        .id = 257, .qr = 1, .opcode = OC_STATUS,
        .aa = 1, .tc = 1, .rd = 1,
        .ra = 1, .z = 1, .rcode = RC_REFUSED,
        .qd_count = 0, .an_count = 0, .ns_count = 0,
        .ar_count = 0
    };
    DnsMessage dns_message;
    dns_message.header = dns_header;
    u_int16_t buffer_size = -1;
    u_int8_t *dns_message_buffer_ptr = dns_message_to_buffer(&dns_message, &buffer_size);
    TEST_ASSERT_EQUAL(DNS_HEADER_SIZE, buffer_size);
    TEST_ASSERT_EQUAL(0x01, dns_message_buffer_ptr[0]);
    TEST_ASSERT_EQUAL(0x01, dns_message_buffer_ptr[1]);
    TEST_ASSERT_EQUAL(0x97, dns_message_buffer_ptr[2]);
    TEST_ASSERT_EQUAL(0x95, dns_message_buffer_ptr[3]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[4]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[5]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[6]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[7]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[8]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[9]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[10]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[11]);
    free(dns_message_buffer_ptr);
}

void dns_message_to_buffer__convert_questions_successfully() {
    const DnsHeader dns_header = {
        .id = 257, .qr = 1, .opcode = OC_STATUS,
        .aa = 1, .tc = 1, .rd = 1,
        .ra = 1, .z = 1, .rcode = RC_REFUSED,
        .qd_count = 2, .an_count = 0, .ns_count = 0,
        .ar_count = 0
    };
    const DnsQuestion dns_question1 = {
        .domain = "test.com", .q_type = TYPE_ALL, .q_class = CLASS_ANY
    };
    const DnsQuestion dns_question2 = {
        .domain = "test.de", .q_type = TYPE_A, .q_class = CLASS_IN
    };
    const DnsQuestion dns_questions[2] = {dns_question1, dns_question2};
    DnsMessage dns_message;
    dns_message.header = dns_header;
    dns_message.questions = dns_questions;
    u_int16_t buffer_size = -1;
    const u_int8_t *dns_message_buffer_ptr = dns_message_to_buffer(&dns_message, &buffer_size);
    TEST_ASSERT_EQUAL(DNS_HEADER_SIZE + 10 + 2 + 2 + 9 + 2 + 2, buffer_size);
    const u_int8_t expected_domain1[10] = {0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00};
    TEST_ASSERT_EQUAL_CHAR_ARRAY(
        expected_domain1,
        dns_message_buffer_ptr + 12,
        10
    );
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[22]);
    TEST_ASSERT_EQUAL(TYPE_ALL, dns_message_buffer_ptr[23]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[24]);
    TEST_ASSERT_EQUAL(CLASS_ANY, dns_message_buffer_ptr[25]);
    const u_int8_t expected_domain2[9] = {0x04, 't', 'e', 's', 't', 0x02, 'd', 'e', 0x00};
    TEST_ASSERT_EQUAL_CHAR_ARRAY(
        expected_domain2,
        dns_message_buffer_ptr + 26,
        9
    );
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[35]);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message_buffer_ptr[36]);
}

void dns_message_to_buffer__convert_answers_successfully() {
    const DnsHeader dns_header = {
        .id = 257, .qr = 1, .opcode = OC_STATUS,
        .aa = 1, .tc = 1, .rd = 1,
        .ra = 1, .z = 1, .rcode = RC_REFUSED,
        .qd_count = 0, .an_count = 1, .ns_count = 0,
        .ar_count = 0
    };
    u_int8_t dns_answer_data[4] = {0x01, 0x02, 0x03, 0x04};
    const DnsRecord dns_answer = {
        .domain = "test.com", .r_type = TYPE_A, .r_class = CLASS_IN,
        .ttl = 65537, .rd_length = 4, .r_data = dns_answer_data
    };
    const DnsRecord dns_answers[1] = {dns_answer};
    DnsMessage dns_message;
    dns_message.header = dns_header;
    dns_message.answers = dns_answers;
    u_int16_t buffer_size = -1;
    const u_int8_t *dns_message_buffer_ptr = dns_message_to_buffer(&dns_message, &buffer_size);
    TEST_ASSERT_EQUAL(DNS_HEADER_SIZE + 10 + 2 + 2 + 4 + 2 + 4, buffer_size);
    const u_int8_t expected_domain[10] = {0x04, 't', 'e', 's', 't', 0x03, 'c', 'o', 'm', 0x00};
    TEST_ASSERT_EQUAL_CHAR_ARRAY(
        expected_domain,
        dns_message_buffer_ptr + 12,
        10
    );
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[22]);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message_buffer_ptr[23]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[24]);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message_buffer_ptr[25]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[26]);
    TEST_ASSERT_EQUAL(0x01, dns_message_buffer_ptr[27]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[28]);
    TEST_ASSERT_EQUAL(0x01, dns_message_buffer_ptr[29]);
    TEST_ASSERT_EQUAL(0x00, dns_message_buffer_ptr[30]);
    TEST_ASSERT_EQUAL(0x04, dns_message_buffer_ptr[31]);
    TEST_ASSERT_EQUAL(0x01, dns_message_buffer_ptr[32]);
    TEST_ASSERT_EQUAL(0x02, dns_message_buffer_ptr[33]);
    TEST_ASSERT_EQUAL(0x03, dns_message_buffer_ptr[34]);
    TEST_ASSERT_EQUAL(0x04, dns_message_buffer_ptr[35]);
}


int main(void) {
    UNITY_BEGIN();
    RUN_TEST(parse_dns_header__successfully);
    RUN_TEST(parse_dns_message__parse_header_successfully);
    RUN_TEST(parse_dns_message__parse_single_question);
    RUN_TEST(parse_dns_message__parse_multiple_questions);
    RUN_TEST(parse_dns_message__parse_questions_with_pointer);
    RUN_TEST(parse_dns_message__parse_questions_with_end_pointer);
    RUN_TEST(parse_dns_message__question_exceeds_max_domain_size);
    RUN_TEST(parse_dns_message__parse_single_answer);
    RUN_TEST(dns_message_to_buffer__convert_header_successfully);
    RUN_TEST(dns_message_to_buffer__convert_questions_successfully);
    RUN_TEST(dns_message_to_buffer__convert_answers_successfully);
    return UNITY_END();
}
