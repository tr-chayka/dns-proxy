#include <dns_helpers.h>
#include <dns_message.h>

#include <assert.h>
#include <stdlib.h>

bool dns_allocate_and_read(dns_buffer* buffer, void** dst, size_t length, enum dns_list_type type);
bool dns_read_name(dns_buffer* buffer, char* str);

bool dns_read_question(dns_buffer* buffer, dns_question* this)
{
	return dns_read_name(buffer, this->qname)
		&& dns_read_ui16(buffer, &this->qtype)
		&& dns_read_ui16(buffer, &this->qclass);
}

bool dns_read_resource_record(dns_buffer* buffer, dns_resource_record* this)
{
	return dns_read_name(buffer, this->name)
		&& dns_read_ui16(buffer, &this->type)
		&& dns_read_ui16(buffer, &this->class)
		&& dns_read_i32(buffer, &this->ttl)
		&& dns_read_ui16(buffer, &this->rdlength)
		&& dns_read_raw(buffer, this->rdata, this->rdlength);
}

bool dns_read_header(dns_buffer* buffer, dns_header* this)
{
	return dns_read_ui16(buffer, &this->id)
		&& dns_read_ui16(buffer, (uint16_t*)&this->flags)
		&& dns_read_ui16(buffer, &this->qdcount)
		&& dns_read_ui16(buffer, &this->ancount)
		&& dns_read_ui16(buffer, &this->nscount)
		&& dns_read_ui16(buffer, &this->arcount);
}


bool dns_read_message(dns_buffer* buffer, dns_message* this)
{
	if (!dns_read_header(buffer, &this->header))
		return false;

	return dns_allocate_and_read(buffer, (void**)&this->question, this->header.qdcount, DNS_LIST_Q);
		// && dns_allocate_and_read(buffer, (void**)&this->answer, this->header.ancount, DNS_LIST_RR)
		// && dns_allocate_and_read(buffer, (void**)&this->authority, this->header.nscount, DNS_LIST_RR)
		// && dns_allocate_and_read(buffer, (void**)&this->additional, this->header.arcount,DNS_LIST_RR);
}

//

bool dns_allocate_and_read(dns_buffer* buffer, void** dst, size_t length, enum dns_list_type type)
{
	if (length == 0)
		return true;

	// allocate
	void *list = (*dst) = NULL;

	switch (type)
	{
		case DNS_LIST_Q:
			list = malloc(sizeof(dns_question) * length);
			break;
		case DNS_LIST_RR:
			list = malloc(sizeof(dns_resource_record) * length);
			break;
	}

	if (list == NULL)
		return false;

	// read
	for (size_t i = 0; i < length; i++)
	{
		bool ok = false;

		switch (type)
		{
			case DNS_LIST_Q:
				ok = dns_read_question(buffer, (dns_question*)&list[i]);
				break;
			case DNS_LIST_RR:
				ok = dns_read_resource_record(buffer, (dns_resource_record*)&list[i]);
				break;
		}

		if (!ok)
		{
			free(list);
			return false;
		}
	}

	*dst = list;
	return true;
}

// read name

enum dns_label_type dns_get_label_type(const dns_buffer* buffer)
{
	const uint8_t header = *buffer->it;

	if (header == 0)
		return DNS_LT_NULL;
	if (header >> 6 == 0x3)
		return DNS_LT_REF;

	return DNS_LT_LABEL;
}

size_t dns_read_label(dns_buffer* buffer, char* str)
{
	const size_t length = *buffer->it++;
	return dns_read_raw(buffer, (uint8_t*)str, length) ? length : 0;
}

/*
size_t dns_read_ref(dns_buffer* buffer, char* str)
{
	dns_buffer ref_buffer = move_to_name_ref(buffer);

	switch (dns_get_label_type(&ref_buffer))
	{
		case DNS_LT_LABEL:
			return dns_read_label(&ref_buffer, str);
		case DNS_LT_REF:
			return dns_read_ref(&ref_buffer, str);
		default:
			return 0;
	}
}
*/

size_t dns_read_name_impl(dns_buffer* buffer, char* str)
{
	char* str_it = str;

	while (buffer->it < buffer->end)
		switch (dns_get_label_type(buffer))
		{
			case DNS_LT_NULL:
				buffer->it++;
				goto EPILOG;

			case DNS_LT_REF:
			{
				dns_buffer ref_buffer = move_to_name_ref(buffer);
				size_t length = dns_read_name_impl(&ref_buffer, str_it);
				return length;
			}

			case DNS_LT_LABEL:
			{
				const size_t expected_length = *buffer->it;
				const size_t actual_length = dns_read_label(buffer, str_it);

				if (expected_length != actual_length)
					return 0;

				str_it[actual_length] = '.';
				str_it += actual_length + 1;
			}
		}

	EPILOG:
		if (str_it <= str)
			return 0;

		assert(str_it[-1] == '.');
		str_it[-1] = 0;

	return 1;
}

bool dns_read_name(dns_buffer* buffer, char* str)
{
	return dns_read_name_impl(buffer, str) > 0;
}