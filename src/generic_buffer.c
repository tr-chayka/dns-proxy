#include <generic_buffer.h>

#include <stdlib.h>
#include <string.h>

void check_and_resize(generic_buffer* this)
{
	if (this->size < this->capacity)
		return;

	const size_t new_capacity = this->capacity * 2;
	void* new_data = malloc(new_capacity * this->element_size); // can be null

	memset(new_data, 0, new_capacity * this->element_size);
	memcpy(this->data, new_data, this->size * this->element_size);
	free(this->data);

	this->capacity = new_capacity;
	this->data = new_data;
}

generic_buffer* generic_buffer_new(size_t capacity, size_t element_size)
{
	generic_buffer* this = malloc(sizeof(generic_buffer));

	if (this == NULL)
		return NULL;

	this->capacity = capacity;
	this->element_size = element_size;
	this->size = 0;
	this->data = malloc(capacity * element_size);
	memset(this->data, 0, capacity * element_size);

	if (this->data == NULL)
	{
		free(this);
		return NULL;
	}

	return this;
}

void generic_buffer_free(generic_buffer* this)
{
	if (this != NULL)
	{
		if (this->data != NULL)
			free(this->data);

		free(this);
	}
}

void generic_buffer_push_back(generic_buffer* this, const void* value)
{
	check_and_resize(this);

	memcpy(this->data + this->size * this->element_size, value, this->element_size);
	this->size++;
}