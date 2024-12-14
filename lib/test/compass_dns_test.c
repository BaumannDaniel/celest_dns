#include "unity.h"
#include "compass_dns.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void parse_dns_header__successfully() {
    const u_int8_t dns_header_bytes[12] = { 0x00, 0x05, 0x8f, 0xb3, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04 };
    const DnsHeader dns_header = parse_dns_header(dns_header_bytes);
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

// not needed when using generate_test_runner.rb
int main(void) {
    UNITY_BEGIN();
    RUN_TEST(parse_dns_header__successfully);
    return UNITY_END();
}