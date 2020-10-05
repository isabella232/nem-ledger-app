#pragma once

#include "nem_types.h"

enum SummaryItemKind {
  SummaryItemNone = 0, // SummaryItemNone always zero
  SummaryItemAddress,
  SummaryItemMessage,
  SummaryItemAmount,
  SummaryItemString,
  SummaryItemSizedString,
  SummaryItemBoolean,
  SummaryItemNumAssets,
  SummaryItemAsset,
  SummaryItemHash
};

struct SummaryItem {
  const char* title;
  enum SummaryItemKind kind;
  union {
    uint64_t u64;
    const char* string;
    const HashData *hash;
    SizedString sized_string;
    const Address *address;
    Message message;
    bool boolean;
    Asset asset;
  };
};

typedef struct SummaryItem SummaryItem;

#define TITLE_SIZE 32
#define TEXT_BUFFER_LENGTH (2 * HASH_SIZE + 1)

extern char G_transaction_summary_title[TITLE_SIZE];
extern char G_transaction_summary_text[TEXT_BUFFER_LENGTH];

#define NUM_GENERAL_ITEMS 12

typedef struct TransactionSummary {
  SummaryItem primary;
  SummaryItem general[NUM_GENERAL_ITEMS];
} TransactionSummary;

void summary_item_set_address(SummaryItem* item, const char* title, const Address *address);
void summary_item_set_message(SummaryItem *item, const char *title, const Message *message);
void summary_item_set_amount(SummaryItem *item, const char *title, uint64_t amount);
void summary_item_set_string(struct SummaryItem *item, const char *title, const char *string);
void summary_item_set_sized_string(SummaryItem *item, const char *title, const SizedString *string);
void summary_item_set_boolean(SummaryItem *item, const char *title, bool value);
void summary_item_set_num_assets(SummaryItem *item, const char *title, int value);
void summary_item_set_asset(SummaryItem *item, const Asset *asset);
void summary_item_set_hash(SummaryItem *item, const char *title, const HashData *hash);

SummaryItem* transaction_summary_primary_item();
SummaryItem* transaction_summary_general_item();

void transaction_summary_reset();
int transaction_summary_get_num_items(size_t *num_items);
int transaction_summary_display_item(size_t item_index);
