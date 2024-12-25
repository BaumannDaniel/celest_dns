#include "unity.h"
#include "compass_dns.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void parse_dns_header__successfully() {
    const u_int8_t dns_header_bytes[12] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x03, 0x00, 0x04
    };
    DnsHeader dns_header;
    parse_dns_header(dns_header_bytes, &dns_header);
    TEST_ASSERT_EQUAL(5, dns_header.id);
    TEST_ASSERT_EQUAL(1, dns_header.qr);
    TEST_ASSERT_EQUAL(1, dns_header.opcode);
    TEST_ASSERT_EQUAL(1, dns_header.aa);
    TEST_ASSERT_EQUAL(1, dns_header.tc);
    TEST_ASSERT_EQUAL(1, dns_header.rd);
    TEST_ASSERT_EQUAL(1, dns_header.ra);
    TEST_ASSERT_EQUAL(3, dns_header.z);
    TEST_ASSERT_EQUAL(3, dns_header.rcode);
    TEST_ASSERT_EQUAL(1, dns_header.qd_count);
    TEST_ASSERT_EQUAL(2, dns_header.an_count);
    TEST_ASSERT_EQUAL(3, dns_header.ns_count);
    TEST_ASSERT_EQUAL(4, dns_header.ar_count);
}

void dns_header_to_buffer__successfully() {
    const DnsHeader dns_header = {
        .id = 257, .qr = 1, .opcode = OC_STATUS,
        .aa = 1, .tc = 1, .rd = 1,
        .ra = 1, .z = 1, .rcode = RC_REFUSED,
        .qd_count = 4, .an_count = 3, .ns_count = 2,
        .ar_count = 1
    };
    u_int8_t buffer[12] = {0};
    dns_header_to_buffer(&dns_header, buffer);
    TEST_ASSERT_EQUAL(0x01, buffer[0]);
    TEST_ASSERT_EQUAL(0x01, buffer[1]);
    TEST_ASSERT_EQUAL(0x97, buffer[2]);
    TEST_ASSERT_EQUAL(0x95, buffer[3]);
    TEST_ASSERT_EQUAL(0x00, buffer[4]);
    TEST_ASSERT_EQUAL(0x04, buffer[5]);
    TEST_ASSERT_EQUAL(0x00, buffer[6]);
    TEST_ASSERT_EQUAL(0x03, buffer[7]);
    TEST_ASSERT_EQUAL(0x00, buffer[8]);
    TEST_ASSERT_EQUAL(0x02, buffer[9]);
    TEST_ASSERT_EQUAL(0x00, buffer[10]);
    TEST_ASSERT_EQUAL(0x01, buffer[11]);
}

void parse_dns_questions__parse_single_question() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01
    };
    DnsQuestion dns_questions[1];
    u_int16_t dns_questions_end_ptr;
    parse_dns_questions(dns_message_buffer, dns_questions, &dns_questions_end_ptr);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_questions[0].q_class);
    TEST_ASSERT_EQUAL(sizeof(dns_message_buffer) - 1, dns_questions_end_ptr);
    free_dns_questions(dns_questions, 1);
}

void parse_dns_questions__parse_multiple_questions() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00,
        0x01, 0x03, 'w', 'w', 'w', 0x02,
        'a', 'b', 0x02, 'e', 'n', 0x00,
        0x00, 0x05, 0x00, 0x02
    };
    DnsQuestion dns_questions[2];
    u_int16_t dns_questions_end_ptr;
    parse_dns_questions(dns_message_buffer, dns_questions, &dns_questions_end_ptr);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_questions[0].q_class);
    TEST_ASSERT_EQUAL_STRING("www.ab.en", dns_questions[1].domain);
    TEST_ASSERT_EQUAL(TYPE_CNAME, dns_questions[1].q_type);
    TEST_ASSERT_EQUAL(CLASS_CS, dns_questions[1].q_class);
    TEST_ASSERT_EQUAL(sizeof(dns_message_buffer) - 1, dns_questions_end_ptr);
    free_dns_questions(dns_questions, 2);
}

void parse_dns_questions__parse_questions_with_pointer() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05,
        0x00, 0x02
    };
    DnsQuestion dns_questions[2];
    u_int16_t dns_questions_end_ptr;
    parse_dns_questions(dns_message_buffer, dns_questions, &dns_questions_end_ptr);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_questions[0].q_class);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_questions[1].domain);
    TEST_ASSERT_EQUAL(TYPE_CNAME, dns_questions[1].q_type);
    TEST_ASSERT_EQUAL(CLASS_CS, dns_questions[1].q_class);
    TEST_ASSERT_EQUAL(sizeof(dns_message_buffer) - 1, dns_questions_end_ptr);
    free_dns_questions(dns_questions, 2);
}

void parse_dns_questions__parse_questions_with_end_pointer() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0x03, 'w', 'w', 'w',
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x02
    };
    DnsQuestion dns_questions[2];
    u_int16_t dns_questions_end_ptr;
    parse_dns_questions(dns_message_buffer, dns_questions, &dns_questions_end_ptr);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_questions[0].q_class);
    TEST_ASSERT_EQUAL_STRING("www.test.com", dns_questions[1].domain);
    TEST_ASSERT_EQUAL(TYPE_CNAME, dns_questions[1].q_type);
    TEST_ASSERT_EQUAL(CLASS_CS, dns_questions[1].q_class);
    TEST_ASSERT_EQUAL(sizeof(dns_message_buffer) - 1, dns_questions_end_ptr);
    free_dns_questions(dns_questions, 2);
}

void parse_dns_records__parse_single_record() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
        0x00, 0x04, 0x01, 0x02, 0x03, 0x04
    };
    DnsRecord dns_records[1];
    u_int16_t dns_records_end_ptr;
    parse_dns_records(dns_message_buffer, dns_records, &dns_records_end_ptr, 12, 1);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_records[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_records[0].r_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_records[0].r_class);
    TEST_ASSERT_EQUAL(sizeof(dns_message_buffer) - 1, dns_records_end_ptr);
    free_dns_records(dns_records, 1);
}

void parse_dns_message__successfully() {
    const u_int8_t dns_message_buffer[] = {
        0x00, 0x05, 0x8f, 0xb3, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01,
        0x04, 't', 'e', 's', 't', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x01, 0x01,
        0x00, 0x04, 0x01, 0x02, 0x03, 0x04
    };
    DnsMessage dns_message;
    parse_dns_message(dns_message_buffer, &dns_message);
    TEST_ASSERT_EQUAL(5, dns_message.header.id);
    TEST_ASSERT_EQUAL(1, dns_message.header.qr);
    TEST_ASSERT_EQUAL(1, dns_message.header.opcode);
    TEST_ASSERT_EQUAL(1, dns_message.header.aa);
    TEST_ASSERT_EQUAL(1, dns_message.header.tc);
    TEST_ASSERT_EQUAL(1, dns_message.header.rd);
    TEST_ASSERT_EQUAL(1, dns_message.header.ra);
    TEST_ASSERT_EQUAL(3, dns_message.header.z);
    TEST_ASSERT_EQUAL(3, dns_message.header.rcode);
    TEST_ASSERT_EQUAL(1, dns_message.header.qd_count);
    TEST_ASSERT_EQUAL(1, dns_message.header.an_count);
    TEST_ASSERT_EQUAL(0, dns_message.header.ns_count);
    TEST_ASSERT_EQUAL(0, dns_message.header.ar_count);
    TEST_ASSERT_EQUAL_STRING("test.com", dns_message.questions[0].domain);
    TEST_ASSERT_EQUAL(TYPE_A, dns_message.questions[0].q_type);
    TEST_ASSERT_EQUAL(CLASS_IN, dns_message.questions[0].q_class);
    free_dns_message(&dns_message);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(parse_dns_header__successfully);
    RUN_TEST(dns_header_to_buffer__successfully);
    RUN_TEST(parse_dns_questions__parse_single_question);
    RUN_TEST(parse_dns_questions__parse_multiple_questions);
    RUN_TEST(parse_dns_questions__parse_questions_with_pointer);
    RUN_TEST(parse_dns_questions__parse_questions_with_end_pointer);
    RUN_TEST(parse_dns_records__parse_single_record);
    RUN_TEST(parse_dns_message__successfully);
    return UNITY_END();
}