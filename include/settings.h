#pragma once
#include <dns_proxy.h>

#include <stdbool.h>

bool dns_read_settings(dns_proxy_settings* this, const char* filename);