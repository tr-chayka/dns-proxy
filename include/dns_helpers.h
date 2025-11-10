#pragma once
#include <dns_buffer.h>
#include <stdbool.h>

enum dns_list_type
{
	DNS_LIST_Q,
	DNS_LIST_RR,
};

enum dns_label_type
{
	DNS_LT_LABEL,
	DNS_LT_REF,
	DNS_LT_NULL,
};

bool dns_read_ui16(dns_buffer* buffer, uint16_t* value);
bool dns_read_i32(dns_buffer* buffer, int32_t* value);
bool dns_read_raw(dns_buffer* buffer, uint8_t* value, size_t length);

dns_buffer move_to_name_ref(dns_buffer* buffer);

void dns_write_ui16(dns_buffer* buffer, uint16_t value);
void dns_write_i32(dns_buffer* buffer, int32_t value);
void dns_write_raw(dns_buffer* buffer, const uint8_t* value, size_t length);