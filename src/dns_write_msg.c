#include <dns_helpers.h>
#include <dns_message.h>

#include <assert.h>

void dns_write_name(dns_buffer* buffer, const char* str);
void dns_write_list(dns_buffer* buffer, const void* list, size_t length, enum dns_list_type type);

void dns_write_question(dns_buffer* buffer, const dns_question* this)
{
	dns_write_name(buffer, this->qname);
	dns_write_ui16(buffer, this->qtype);
	dns_write_ui16(buffer, this->qclass);
}

void dns_write_resource_record(dns_buffer* buffer, const dns_resource_record* this)
{
	dns_write_name(buffer, this->name);
	dns_write_ui16(buffer, this->type);
	dns_write_ui16(buffer, this->class);
	dns_write_i32(buffer, this->ttl);
	dns_write_ui16(buffer, this->rdlength);
	dns_write_raw(buffer, this->rdata, this->rdlength);
}

void dns_write_header(dns_buffer* buffer, const dns_header* this)
{
	dns_write_ui16(buffer, this->id);
	dns_write_ui16(buffer, *(const uint16_t*)&this->flags);
	dns_write_ui16(buffer, this->qdcount);
	dns_write_ui16(buffer, this->ancount);
	dns_write_ui16(buffer, this->nscount);
	dns_write_ui16(buffer, this->arcount);
}

void dns_write_message(dns_buffer* buffer, const dns_message* this)
{
	dns_write_header(buffer, &this->header);
	dns_write_list(buffer, this->question, this->header.qdcount, DNS_LIST_Q);
	dns_write_list(buffer, this->answer, this->header.ancount, DNS_LIST_RR);
	dns_write_list(buffer, this->authority, this->header.nscount, DNS_LIST_RR);
	dns_write_list(buffer, this->additional, this->header.arcount, DNS_LIST_RR);
}

void dns_write_list(dns_buffer* buffer, const void* list, size_t length, enum dns_list_type type)
{
	if (buffer == NULL || list == NULL)
		return;

	for (size_t i = 0; i < length; i++)
		switch (type)
		{
			case DNS_LIST_Q:
				dns_write_question(buffer, list + i);
				break;

			case DNS_LIST_RR:
				dns_write_resource_record(buffer, list + i);
				break;
		}
}

void dns_write_name(dns_buffer* buffer, const char* str)
{
	if (buffer == NULL || str == NULL)
		return;

	size_t label_start = 0;
	size_t position = 0;
	bool end = false;

	while (!end)
	{
		switch (str[position])
		{
			case '.':
				assert(position - label_start < DNS_LABEL_MAX_LENGTH);
				assert(position > label_start);

				*buffer->it++ = position - label_start; // length first
				dns_write_raw(buffer, (const uint8_t*)str + label_start, position - label_start);
				label_start = position + 1;
				break;

			case 0:
				assert(position - label_start < DNS_LABEL_MAX_LENGTH);
				assert(position > label_start);

				*buffer->it++ = position - label_start; // length first
				dns_write_raw(buffer, (const uint8_t*)str + label_start, position - label_start);
				*buffer->it++ = 0; // null terminator
				end = true;
				break;

			default:
				break;
		}

		position++;
	}
}