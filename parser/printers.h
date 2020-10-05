#pragma once

#include "nem_types.h"

#include <stdint.h>

int print_string(const char *string, char *out, size_t out_length);
int print_sized_string(const SizedString *string, char *out, size_t out_length);
int print_amount(uint64_t amount, uint8_t divisibility, const char *asset, char *out);
int print_address(const Address *address, char *out, size_t out_length);
int print_msg(const Message *message, char *out, size_t out_length);
int print_num_assets(uint64_t num, char *out, size_t out_length);
int print_asset(const Asset *asset, char *out, size_t out_length);
int print_boolean(bool boolean, char *out, size_t out_length);
int print_hash(const HashData *hash, char *out, size_t out_length);
