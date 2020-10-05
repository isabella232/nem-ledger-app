#include "transaction_parser.h"

#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  TransferTransaction transfer;
  ImportanceTransferTransaction importance_transfer;
  MultisigAggregateModificationTransaction multisig_aggregated_modification;
  ProvisionNamespaceTransaction provision_namespace;
  AssetDefinitionCreationTransaction mosaic_definition_creation;
  MosaicSupplyChangeTransaction mosaic_supply_change;
  MultisigTransaction multisig;
  MultisigSignatureTransaction multisig_signature;

  Parser parser = {Data, Size};
  TransactionHeader header;
  if (parse_transaction_header(&parser, &header)) {
    return 0;
  }

  switch (header.type) {
  case TransferType: {
    parse_transfer_transaction(&parser, &transfer, &header);
    break;
  case ImportanceTransferType:parse_importance_transfer_transaction(&parser, &importance_transfer, &header);
    break;
  case MultisigAggregateModificationType:
    parse_multisig_aggregate_modification_transaction(&parser,
                                                      &multisig_aggregated_modification,
                                                      &header);
    break;
  case ProvisionNamespaceType:parse_provision_namespace_transaction(&parser, &provision_namespace, &header);
    break;
  case MosaicDefinitionCreationType:
    parse_mosaic_definition_creation_transaction(&parser,
                                                 &mosaic_definition_creation,
                                                 &header);
    break;
  case MosaicSupplyChangeType:parse_mosaic_supply_change_transaction(&parser, &mosaic_supply_change, &header);
    break;
  case MultisigSignatureType:parse_multisig_signature_transaction(&parser, &multisig_signature, &header);
    break;
  case MultisigType:parse_multisig_transaction(&parser, &multisig, &header);
    break;
  }
  default:exit(0);
  }
  return 0;  // Non-zero return values are reserved for future use.
}