#include "nem_types.h"
#include "transaction_summary.h"

int print_transfer_transaction(const TransferTransaction *transaction, const TransactionHeader *header) {
  SummaryItem *item = transaction_summary_primary_item();
  summary_item_set_string(item, "Confirm", "Transfer TX");

  item = transaction_summary_general_item();
  summary_item_set_address(item, "Recipient", transaction->recipient);

  item = transaction_summary_general_item();
  summary_item_set_message(item, "Message", &transaction->message);

  item = transaction_summary_general_item();
  summary_item_set_amount(item, "Fee", header->fee);

  if (transaction->num_assets == 0) {
    item = transaction_summary_general_item();
    summary_item_set_amount(item, "Amount", transaction->amount);
  } else {
    item = transaction_summary_general_item();
    summary_item_set_num_assets(item, "Mosaics", transaction->num_assets);
    for (int i = 0; i < transaction->num_assets; i++) {
      item = transaction_summary_general_item();
      summary_item_set_asset(item, &transaction->assets[i]);
    }
  }
  return 0;
}

static int print_asset_definition(const AssetDefinition *asset_definition) {
  SummaryItem  *item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Description", &asset_definition->description);

  // Property 1: initialSupply
  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Initial Supply", &asset_definition->properties[1].value);

  // Property 0: divisibility
  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Divisibility", &asset_definition->properties[0].value);

  // Property 2: mutableSupply
  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Mutable Supply", &asset_definition->properties[2].value);

  // Property 3: transferable
  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Transferable", &asset_definition->properties[3].value);

  item = transaction_summary_general_item();
  summary_item_set_boolean(item, "Requires Levy", asset_definition->has_levy);
  return 0;
}

int print_mosaic_definition_creation_transaction(const AssetDefinitionCreationTransaction *transaction, const TransactionHeader *header) {
  SummaryItem *item = transaction_summary_primary_item();
  summary_item_set_string(item, "Confirm", "Create Mosaic");

  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Namespace", &transaction->asset_definition.id.namespace_id);

  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Mosaic Name", &transaction->asset_definition.id.name);

  item = transaction_summary_general_item();
  summary_item_set_amount(item, "Fee", header->fee);

  item = transaction_summary_general_item();
  summary_item_set_amount(item, "Rental Fee", transaction->creation_fee);

  print_asset_definition(&transaction->asset_definition);
  return 0;
}

int print_multisig_transaction(const MultisigTransaction *transaction, const TransactionHeader *header) {
  switch (transaction->header.type) {
  case TransferType:
    if (print_transfer_transaction(&transaction->transfer, &transaction->header)) {
      return -1;
    }
    break;
  default:return -1;
  }
  return 0;
}

int print_multisig_signature_transaction(const MultisigSignatureTransaction *transaction,
                                         const TransactionHeader *header) {
  SummaryItem *item = transaction_summary_primary_item();
  summary_item_set_string(item, "Confirm", "Multisig signature");

  item = transaction_summary_general_item();
  summary_item_set_address(item, "Cosign tx for", transaction->other_account);

  item = transaction_summary_general_item();
  summary_item_set_hash(item, "SHA hash", transaction->other_hash);

  item = transaction_summary_general_item();
  summary_item_set_amount(item, "Multisig fee", header->fee);
  return 0;
}

int print_provision_namespace_creation(const ProvisionNamespaceTransaction *transaction,
                                       const TransactionHeader *header) {
  SummaryItem *item = transaction_summary_primary_item();
  summary_item_set_string(item, "Confirm", "Namespace TX");

  item = transaction_summary_general_item();
  summary_item_set_address(item, "Sink Address", transaction->rental_fee_sink);

  item = transaction_summary_general_item();
  summary_item_set_amount(item, "Rental Fee", transaction->rental_fee);

  item = transaction_summary_general_item();
  summary_item_set_amount(item, "Fee", header->fee);

  item = transaction_summary_general_item();
  summary_item_set_sized_string(item, "Namespace", &transaction->new_part);

  item = transaction_summary_general_item();
  if (transaction->parent.length == 0) {
    summary_item_set_string(item, "Parent Name", "<New namespace>");
  } else {
    summary_item_set_sized_string(item, "Parent Name", &transaction->parent);
  }
  return 0;
}

int print_multisig_aggregate_modification_transaction(const MultisigAggregateModificationTransaction *transaction,
                                                      const TransactionHeader *header) {
  SummaryItem *item = transaction_summary_primary_item();
  summary_item_set_string(item, "Confirm", "Convert to Multisig");

  item = transaction_summary_general_item();
  // summary_item_set_address(item, "Converted Account", transaction.)

  return -1;
}