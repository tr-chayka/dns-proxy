#include <dns_blacklist.h>
#include <generic_buffer.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool dns_blacklist_init(dns_blacklist* this, const char* filename)
{
	bool result = false;
	FILE *file = fopen(filename, "r");

	if (file == NULL)
		return false;

	this->domains = generic_buffer_new(64, sizeof(char*));

	if (this->domains == NULL)
		goto END;

	generic_buffer* line_buffer = generic_buffer_new(64, sizeof(char));

	if (line_buffer == NULL)
	{
		generic_buffer_free(this->domains);
		goto END;
	}

	while (1)
	{
		char ch = 0;
		const size_t read = fread(&ch, sizeof(char), 1, file);

		if (read == 0 || ch == '\n')
		{
			if (*(char*)(line_buffer->data) != 0) //
				generic_buffer_push_back(this->domains, &line_buffer->data); // move

			free(line_buffer);

			if (read == 0)
			{
				result = true;
				goto END;
			}

			line_buffer = generic_buffer_new(64, sizeof(char));
		}
		else
		{
			generic_buffer_push_back(line_buffer, &ch);
		}
	}

	END:
	fclose(file);
	return result;
}

void dns_blacklist_dispose(dns_blacklist* this)
{
	generic_buffer_free(this->domains);
}

bool dns_blacklist_find(const dns_blacklist* this, const char* domain)
{
	if (this == NULL || this->domains == NULL)
		return false;

	char** data = this->domains->data;
	if (data == NULL) return false;

	for (char** it = data; *it != NULL; it++)
		if (strcmp(*it, domain) == 0)
			return true;

	return false;
}