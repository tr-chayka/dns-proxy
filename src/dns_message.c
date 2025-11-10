#include <dns_message.h>

#include <stdlib.h>
#include <string.h>

bool dns_create_request(dns_message* msg, uint16_t id, bool ip_only, const char** names, size_t count)
{
	size_t message_size = DNS_MESSAGE_HEADER_SIZE;

	memset(msg, 0, sizeof(dns_message));
	msg->header.id = id;
	msg->header.flags.rd = ip_only;
	msg->header.qdcount = count;

	if (count == 0)
		return true;

	msg->question = (dns_question*)malloc(sizeof(dns_question) * count);

	if (msg->question == NULL)
		return false;

	for (size_t i = 0; i < count; i++)
	{
		const size_t name_len = strlen(names[i]);

		if (name_len >= DNS_QNAME_MAX_LENGTH)
			return false;

		strcpy(msg->question[i].qname, names[i]);
		msg->question[i].qtype = DNS_TYPE_A;
		msg->question[i].qclass = DNS_CLASS_IN;

		message_size += name_len + 2; // size for the first fragment & null-terminator
		message_size += 2 * sizeof(uint16_t); // type & class fields size
	}

	return message_size < DNS_UDP_MAX_LENGTH;
}