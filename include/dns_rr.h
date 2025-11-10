#pragma once
#include <stdint.h>

typedef enum
{
	DNS_RR_HINFO,
	DNS_RR_MB,
	DNS_RR_MD,
	DNS_RR_MF,
	DNS_RR_MG,
	DNS_RR_MINFO,
	DNS_RR_MR,
	DNS_RR_MX,
	DNS_RR_NULL,
	DNS_RR_NS,
	DNS_RR_PTR,
	DNS_RR_SOA,
	DNS_RR_TXT,
	DNS_RR_WKS,
	DNS_RR_OPT,
} dns_rr_data_type;

typedef struct
{
	char name[256];

	uint16_t type;
	uint16_t class;
	int32_t ttl;

	dns_rr_data_type data_type;
	uint16_t rdlength;
	uint8_t rdata[256];
} dns_rr;