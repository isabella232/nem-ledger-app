#include "printers.h"
#include "nem_types.h"

#include <string.h>
#ifndef _WIN32
#include <bsd/string.h>
#endif

static const uint8_t AMOUNT_MAX_SIZE = 17;

int print_string(const char *string, char *out, size_t out_length) {
#ifdef _WIN32
  strncpy_s(out, out_length, string, _TRUNCATE);
#else
  strlcpy(out, string, out_length);
#endif
  return 0;
}

int print_sized_string(const SizedString *string, char *out, size_t out_length) {
  size_t len;
  if (out_length < string->length + 1) {
    len = out_length;
  } else {
    len = string->length + 1;
  }
  return print_string(string->string, out, len);
}

int print_msg(const Message *message, char *out, size_t out_length) {
  switch (message->type) {
  case MessageNone:
    print_string("<empty msg>", out, out_length);
    break;
  case MessagePlain:
    print_sized_string(&message->plain, out, out_length);
    break;
  case MessageEncrypted:
    print_string("<encrypted msg>", out, out_length);
    break;
  }
  return 0;
}

int print_address(const Address *address, char *out, size_t out_length) {
  if (out_length < ADDRESS_SIZE + 1) {
    return -1;
  }
  strncpy(out, (const char *)address, ADDRESS_SIZE);
  out[ADDRESS_SIZE] = 0;
  return 0;
}

#include <stdio.h>

int print_num_assets(uint64_t num, char *out, size_t out_length) {
  snprintf(out, out_length, "Found %d mosaics", (int)num);
  return 0;
}

int print_asset(const Asset *asset, char *out, size_t out_length) {
  char asset_name[32];

  if (asset->asset_id.name.length > sizeof(asset_name) - 1) {
    return -1;
  }
  memcpy(asset_name, asset->asset_id.name.string, asset->asset_id.name.length);
  asset_name[asset->asset_id.name.length] = 0;

  if (strcmp(asset_name, "xem") == 0 || strcmp(asset_name, "nem") == 0) {
    print_amount(asset->quantity, 6, asset_name, out);
  } else {
    if (asset->quantity > INT32_MAX) {
      return -1;
    }
    snprintf(out, out_length, "%d %s", (int32_t) asset->quantity, asset_name);
  }
  return 0;
}

int print_boolean(bool boolean, char *out, size_t out_length) {
  const char *value = boolean ? "Yes" : "No";
  return print_string(value, out, out_length);
}

static char hex2Ascii(uint8_t input) {
  uint8_t c;
  if (input < 10) {
    c = input + '0';
  } else {
    c = input + 'a' - 10;
  }
  return c;
}

int print_hash(const HashData *hash, char *out, size_t out_length) {
  if (out_length < 2 * HASH_SIZE + 1) {
    return -1;
  }
  for (int i = 0; i < HASH_SIZE; i++) {
    out[2 * i] = hex2Ascii(hash->data[i] >> 4u);
    out[2 * i + 1] = hex2Ascii(hash->data[i] & 0xfu);
  }
  out[2 * HASH_SIZE] = 0;
  return 0;
}

int print_amount(uint64_t amount, uint8_t divisibility, const char *asset, char *out) {
  char buffer[AMOUNT_MAX_SIZE];
  uint64_t dVal = amount;
  int i, j;

  // If the amount can't be represented safely in JavaScript, signal an error
  //if (MAX_SAFE_INTEGER < amount) THROW(0x6a80);

  memset(buffer, 0, AMOUNT_MAX_SIZE);
  for (i = 0; dVal > 0 || i < 7; i++) {
    if (dVal > 0) {
      buffer[i] = (dVal % 10) + '0';
      dVal /= 10;
    } else {
      buffer[i] = '0';
    }
    if (i == divisibility - 1) { // divisibility
      i += 1;
      buffer[i] = '.';
      if (dVal == 0) {
        i += 1;
        buffer[i] = '0';
      }
    }
    if (i >= AMOUNT_MAX_SIZE) {
      return -1;
    }
  }
  // reverse order
  for (i -= 1, j = 0; i >= 0 && j < AMOUNT_MAX_SIZE-1; i--, j++) {
    out[j] = buffer[i];
  }
  // strip trailing 0s
  for (j -= 1; j > 0; j--) {
    if (out[j] != '0') break;
  }
  j += 1;

  // strip trailing .
  if (out[j-1] == '.') j -= 1;

  if (asset) {
    // qualify amount
    out[j++] = ' ';
    strcpy(out + j, asset);
    out[j+strlen(asset)] = '\0';
  } else {
    out[j] = '\0';
  }
  return 0;
}
