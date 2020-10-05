#pragma once

#include "nem_types.h"
#include "printers.h"
#include "transaction_summary.h"

int print_transfer_transaction(const TransferTransaction *transaction, const TransactionHeader *header);
int print_mosaic_definition_creation_transaction(const AssetDefinitionCreationTransaction *transaction,
                                                 const TransactionHeader *header);
int print_multisig_transaction(const MultisigTransaction *transaction, const TransactionHeader *header);
int print_multisig_signature_transaction(const MultisigSignatureTransaction *transaction,
                                         const TransactionHeader *header);
int print_provision_namespace_creation(const ProvisionNamespaceTransaction *transaction,
                                       const TransactionHeader *header);
int print_multisig_aggregate_modification_transaction(const MultisigAggregateModificationTransaction *transaction,
                                                      const TransactionHeader *header);
