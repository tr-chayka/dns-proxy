#pragma once
#include <stddef.h>

typedef struct
{
	void* data;
	size_t capacity;
	size_t size;
	size_t element_size;
} generic_buffer;

generic_buffer* generic_buffer_new(size_t capacity, size_t element_size);
void generic_buffer_free(generic_buffer* this);
void generic_buffer_push_back(generic_buffer* this, const void* value);
