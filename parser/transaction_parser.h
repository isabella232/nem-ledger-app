#pragma once

#include "nem_types.h"

#include <stddef.h>
#include <stdint.h>

typedef struct Parser {
  const uint8_t *buffer;
  size_t buffer_length;
} Parser;

int parse_transaction_header(Parser *parser, TransactionHeader *header);


int parse_transfer_transaction(Parser *parser, TransferTransaction *transaction, TransactionHeader *header);
int parse_importance_transfer_transaction(Parser *parser,
                                          ImportanceTransferTransaction *transaction,
                                          TransactionHeader *header);
int parse_multisig_aggregate_modification_transaction(Parser *parser,
                                                      MultisigAggregateModificationTransaction *transaction,
                                                      struct TransactionHeader *header);
int parse_multisig_signature_transaction(Parser *parser,
                                         MultisigSignatureTransaction *transaction,
                                         TransactionHeader *header);
int parse_multisig_transaction(Parser *parser, MultisigTransaction *transaction, TransactionHeader *header);
int parse_provision_namespace_transaction(Parser *parser,
                                          ProvisionNamespaceTransaction *transaction,
                                          TransactionHeader *header);
int parse_mosaic_definition_creation_transaction(Parser *parser,
                                                 AssetDefinitionCreationTransaction *transaction,
                                                 TransactionHeader *header);
int parse_mosaic_supply_change_transaction(Parser *parser,
                                           MosaicSupplyChangeTransaction *transaction,
                                           TransactionHeader *header);
