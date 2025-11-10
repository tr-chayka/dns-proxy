#include <dns_helpers.h>

#include <string.h>
#include <sys/types.h>

bool dns_read_ui16(dns_buffer* buffer, uint16_t* value)
{
	if (buffer->it + sizeof(uint16_t) > buffer->end)
		return false;

	*value = ntohs(*(uint16_t*)(buffer->it));
	buffer->it += sizeof(uint16_t);
	return true;
}

bool dns_read_i32(dns_buffer* buffer, int32_t* value)
{
	if (buffer->it + sizeof(int32_t) > buffer->end)
		return false;

	*value = ntohl(*(int32_t*)(buffer->it));
	buffer->it += sizeof(int32_t);
	return true;
}

bool dns_read_raw(dns_buffer* buffer, uint8_t* value, size_t length)
{
	if (length > buffer->end - buffer->it)
		return false;

	memcpy(value, buffer->it, length);
	buffer->it += length;
	return true;
}

dns_buffer move_to_name_ref(dns_buffer* buffer)
{
	uint16_t ref_addr;
	dns_read_ui16(buffer, &ref_addr);
	ref_addr &= (uint16_t)0x3FFF;

	dns_buffer result;
	result.begin = buffer->begin;
	result.end = buffer->end;
	result.it = result.begin + ref_addr;

	return result;
}

void dns_write_ui16(dns_buffer* buffer, uint16_t value)
{
	*(uint16_t*)(buffer->it) = htons(value);
	buffer->it += sizeof(uint16_t);
}

void dns_write_i32(dns_buffer* buffer, int32_t value)
{
	*(int32_t*)(buffer->it) = htonl(value);
	buffer->it += sizeof(int32_t);
}

void dns_write_raw(dns_buffer* buffer, const uint8_t* value, size_t length)
{
	memcpy(buffer->it, value, length);
	buffer->it += length;
}