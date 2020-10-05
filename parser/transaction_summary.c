#include "transaction_summary.h"
#include "printers.h"

#include <string.h>

static TransactionSummary G_transaction_summary;

char G_transaction_summary_title[TITLE_SIZE];
char G_transaction_summary_text[TEXT_BUFFER_LENGTH];

void summary_item_set_address(SummaryItem* item, const char* title, const Address *address) {
  item->kind = SummaryItemAddress;
  item->title = title;
  item->address = address;
}

void summary_item_set_message(SummaryItem *item, const char *title, const Message *message) {
  item->kind = SummaryItemMessage;
  item->title = title;

  item->message.type = message->type;

  if (item->message.type == MessagePlain) {
    item->message.plain.length = message->plain.length;
    item->message.plain.string = message->plain.string;
  } else if (item->message.type == MessageEncrypted) {
    item->message.encrypted.length = message->encrypted.length;
    item->message.encrypted.data = message->encrypted.data;
  }
}

void summary_item_set_amount(SummaryItem *item, const char *title, uint64_t amount) {
  item->kind = SummaryItemAmount;
  item->title = title;
  item->u64 = amount;
}

void summary_item_set_string(struct SummaryItem *item, const char *title, const char *string) {
  item->kind = SummaryItemString;
  item->title = title;
  item->string = string;
}

void summary_item_set_sized_string(SummaryItem *item, const char *title, const SizedString *string) {
  item->kind = SummaryItemSizedString;
  item->title = title;
  item->sized_string.string = string->string;
  item->sized_string.length = string->length;
}

void summary_item_set_boolean(SummaryItem *item, const char *title, bool value) {
  item->kind = SummaryItemBoolean;
  item->title = title;
  item->boolean = value;
}

void summary_item_set_hash(struct SummaryItem *item, const char *title, const HashData *hash) {
  item->kind = SummaryItemHash;
  item->title = title;
  item->hash = hash;
}

void summary_item_set_num_assets(SummaryItem *item, const char *title, int value) {
  item->kind = SummaryItemNumAssets;
  item->title = title;
  item->u64 = value;
}

void summary_item_set_asset(SummaryItem *item, const Asset *asset) {
  item->kind = SummaryItemAsset;

  item->title = "Raw units";
  if (asset->asset_id.name.length == 3) {
    if (strncmp(asset->asset_id.name.string, "xem", 3) == 0 || strncmp(asset->asset_id.name.string, "nem", 3) == 0) {
      item->title = "Amount";
    }
  }
  item->asset.asset_id.name.string = asset->asset_id.name.string;
  item->asset.asset_id.name.length = asset->asset_id.name.length;
  item->asset.quantity = asset->quantity;
}

static SummaryItem* summary_item_as_unused(SummaryItem* item) {
  if (item->kind == SummaryItemNone) {
    return item;
  }
  return NULL;
}

SummaryItem* transaction_summary_general_item() {
  for (size_t i = 0; i < NUM_GENERAL_ITEMS; i++) {
    SummaryItem* item = &G_transaction_summary.general[i];
    if (summary_item_as_unused(item) != NULL) {
      return item;
    }
  }
  return NULL;
}

SummaryItem* transaction_summary_primary_item() {
  SummaryItem* item = &G_transaction_summary.primary;
  return summary_item_as_unused(item);
}

void transaction_summary_reset() {
  memset(&G_transaction_summary, 0, sizeof(TransactionSummary));
  memset(&G_transaction_summary_title, 0, TITLE_SIZE);
  memset(&G_transaction_summary_text, 0, TEXT_BUFFER_LENGTH);
}

static int transaction_summary_update_display_for_item(const SummaryItem *item) {
  switch (item->kind) {
  case SummaryItemAmount:
    if (print_amount(item->u64, 6, "xem", G_transaction_summary_text)) {
      return -1;
    }
    break;
  case SummaryItemAddress:
    if (print_address(item->address, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemMessage:
    if (print_msg(&item->message, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemString:
    if (print_string(item->string, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemSizedString:
    if (print_sized_string(&item->sized_string, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemBoolean:
    if (print_boolean(item->boolean, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemNumAssets:
    if (print_num_assets(item->u64, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemAsset:
    if (print_asset(&item->asset, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  case SummaryItemHash:
    if (print_hash(item->hash, G_transaction_summary_text, TEXT_BUFFER_LENGTH)) {
      return -1;
    }
    break;
  default:
    return -1;
  }
  return print_string(item->title, G_transaction_summary_title, TITLE_SIZE);
}

int transaction_summary_display_item(size_t item_index) {
  SummaryItem *item = NULL;

  if (item_index == 0) {
    item = &G_transaction_summary.primary;
  } else {
    item = &G_transaction_summary.general[item_index - 1];
    if (summary_item_as_unused(item) != NULL) {
      return -1;
    }
  }
  return transaction_summary_update_display_for_item(item);
}

int transaction_summary_get_num_items(size_t *num_items) {
  *num_items = 1; // primary item
  for (size_t i = 0; i < NUM_GENERAL_ITEMS; i++) {
    if (summary_item_as_unused(&G_transaction_summary.general[i]) == NULL) {
      *num_items += 1;
    }
  }
  return 0;
}