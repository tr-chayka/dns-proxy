#pragma once
#include <dns_buffer.h>

#include <stdbool.h>
#include <stdint.h>

enum dns_type
{
	DNS_TYPE_A = 0x1,
	DNS_TYPE_NS = 0x2,
	DNS_TYPE_MD = 0x3,
	DNS_TYPE_MF = 0x4,
	DNS_TYE_CNAME = 0x5,
	DNS_TYPE_SOA = 0x6,
	DNS_TYPE_MB = 0x7,
	DNS_TYPE_MG = 0x8,
	DNS_TYPE_MR = 0x9,
	DNS_TYPE_NULL = 0xA,
	DNS_TYPE_WKS = 0xB,
	DNS_TYPE_PTR = 0xC,
	DNS_TYPE_HINFO = 0xD,
	DNS_TYPE_MX = 0xE,
	DNS_TYPE_TXT = 0xF,
};

enum dns_class
{
	DNS_CLASS_IN = 0x1,
	DNS_CLASS_CS = 0x2,
	DNS_CLASS_CH = 0x3,
	DNS_CLASS_HS = 0x4,
};

#define DNS_QNAME_MAX_LENGTH (uint16_t)256
#define DNS_LABEL_MAX_LENGTH (uint16_t)64
#define DNS_UDP_MAX_LENGTH (uint16_t)512
#define DNS_MESSAGE_HEADER_SIZE (uint16_t)12

typedef struct
{
	uint16_t rcode	: 4;
	uint16_t z		: 3;
	uint16_t ra		: 1;

	uint16_t rd		: 1;
	uint16_t tc		: 1;
	uint16_t aa		: 1;
	uint16_t opcode	: 4;
	uint16_t qr		: 1;
} dns_flags;

typedef struct
{
	uint16_t id;
	dns_flags flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} dns_header;

typedef struct
{
	char qname[DNS_QNAME_MAX_LENGTH];
	uint16_t qtype;
	uint16_t qclass;
} dns_question;

typedef struct
{
	char name[DNS_QNAME_MAX_LENGTH];
	uint16_t type;
	uint16_t class;
	int32_t ttl;
	uint16_t rdlength;
	uint8_t rdata[DNS_QNAME_MAX_LENGTH];
} dns_resource_record;

typedef struct
{
	dns_header header;
	dns_question* question;
	dns_resource_record* answer;
	dns_resource_record* authority;
	dns_resource_record* additional;
} dns_message;

bool dns_read_message(dns_buffer* buffer, dns_message* this);
void dns_write_message(dns_buffer* buffer, const dns_message* this);

// test
bool dns_create_request(dns_message* msg, uint16_t id, bool ip_only, const char* names[], size_t count);