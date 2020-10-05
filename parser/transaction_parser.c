#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "nem_types.h"
#include "transaction_parser.h"

#define PARSER_CHK(x) do {int err = x; if (err) return err;} while (0)

static int check_buffer_length(Parser* parser, size_t num) {
  return parser->buffer_length < num ? -1 : 0;
}

static void advance(Parser *parser, size_t num) {
  parser->buffer += num;
  parser->buffer_length -= num;
}

static int parse_u32(Parser *parser, uint32_t *value) {
  PARSER_CHK(check_buffer_length(parser, sizeof(uint32_t)));
  memcpy(value, parser->buffer, sizeof(uint32_t));
  advance(parser, sizeof(uint32_t));
  return 0;
}

static int parse_u64(Parser *parser, uint64_t *value) {
  uint32_t lower, upper;
  PARSER_CHK(parse_u32(parser, &lower));
  PARSER_CHK(parse_u32(parser, &upper));
  *value = ((uint64_t)upper << 32u) | lower;
  return 0;
}

static int parse_data(Parser *parser, const uint8_t **data, size_t *data_length) {
  uint32_t len;
  PARSER_CHK(parse_u32(parser, &len));
  PARSER_CHK(check_buffer_length(parser, len));
  *data = parser->buffer;
  *data_length = len;
  advance(parser, len);
  return 0;
}

static int parse_sized_string(Parser *parser, SizedString *str) {
  uint32_t len;

  PARSER_CHK(parse_u32(parser, &len));
  if (len == 0xffffffff) {
    str->string = NULL;
    str->length = 0;
  } else {
    PARSER_CHK(check_buffer_length(parser, len));

    // TODO: sanity check? Make sure string does not contain zeroes
    str->string = (const char *)parser->buffer;
    str->length = len;
    advance(parser, len);
  }
  return 0;
}

static int parse_message(Parser *parser, Message *message) {
  const uint8_t *msg_data;
  size_t msg_length;

  PARSER_CHK(parse_data(parser, &msg_data, &msg_length));
  if (msg_length == 0) {
    message->type = MessageNone;
    return 0;
  }

  Parser msg_parser = {msg_data, msg_length};
  uint32_t msg_type;
  PARSER_CHK(parse_u32(&msg_parser, &msg_type));
  if (msg_type == MessagePlain) {
    PARSER_CHK(parse_sized_string(&msg_parser, &message->plain));
  } else if (msg_type == MessageEncrypted) {
    PARSER_CHK(parse_data(&msg_parser, &message->encrypted.data, &message->encrypted.length));
  } else {
    return -1;
  }
  message->type = msg_type;
  return 0;
}

static int parse_account(Parser *parser, const Account **account) {
  const uint8_t *data;
  size_t len;
  if (parse_data(parser, &data, &len)) {
    return -1;
  }
  if (len != ACCOUNT_SIZE) {
    return -1;
  }
  *account = (const Account *)data;
  return 0;
}

static int parse_address(Parser *parser, const Address **address) {
  // TODO: check address charset
  const uint8_t *data;
  size_t len;
  if (parse_data(parser, &data, &len)) {
    return -1;
  }
  if (len != ADDRESS_SIZE) {
    return -1;
  }
  *address = (const Address *)data;
  return 0;
}

static int parse_hash(Parser *parser, const HashData **hash) {
  const uint8_t *data;
  size_t len;
  if (parse_data(parser, &data, &len)) {
    return -1;
  }
  if (len != HASH_SIZE) {
    return -1;
  }
  *hash = (HashData *)data;
  return 0;
}

static int parse_version_and_network(Parser *parser, Version *version, Network *network) {
  uint32_t value;

  PARSER_CHK(parse_u32(parser, &value));
  int nid = value >> 24u;
  if (nid != NetworkMainnet && nid != NetworkTestnet) {
    return -1;
  }
  uint32_t v = value & 0xffffffu;
  if (v != Version1 && v != Version2) {
    return -1;
  }
  *network = nid;
  *version = v;
  return 0;
}

static int parse_asset_property(Parser *parser, AssetProperty *property) {
  PARSER_CHK(parse_sized_string(parser, &property->name));
  PARSER_CHK(parse_sized_string(parser, &property->value));
  return 0;
}

static int parse_asset_id(Parser *parser, AssetId *asset_id) {
  PARSER_CHK(parse_sized_string(parser, &asset_id->namespace_id));
  PARSER_CHK(parse_sized_string(parser, &asset_id->name));
  return 0;
}

static int parse_asset(Parser *parser, Asset *asset) {
  Parser asset_id_parser;

  PARSER_CHK(parse_data(parser, &asset_id_parser.buffer, &asset_id_parser.buffer_length));
  PARSER_CHK(parse_asset_id(&asset_id_parser, &asset->asset_id));
  if (asset_id_parser.buffer_length != 0) {
    return -1;
  }
  PARSER_CHK(parse_u64(parser, &asset->quantity));
  return 0;
}

static int parse_asset_definition(Parser *parser, AssetDefinition *asset_definition) {
  Parser asset_id_parser, asset_property_parser;

  PARSER_CHK(parse_account(parser, &asset_definition->creator));
  PARSER_CHK(parse_data(parser, &asset_id_parser.buffer, &asset_id_parser.buffer_length));
  PARSER_CHK(parse_asset_id(&asset_id_parser, &asset_definition->id));
  if (asset_id_parser.buffer_length != 0) {
    return -1;
  }
  PARSER_CHK(parse_sized_string(parser, &asset_definition->description));

  // Parse asset properties
  uint32_t num_properties;
  parse_u32(parser, &num_properties);
  if (num_properties != ASSET_PROPERTIES_NUM) {
    return -1;
  }
  // TODO: check property names?
  for (int i = 0; i < ASSET_PROPERTIES_NUM; i++) {
    PARSER_CHK(parse_data(parser, &asset_property_parser.buffer, &asset_property_parser.buffer_length));
    PARSER_CHK(parse_asset_property(&asset_property_parser, &asset_definition->properties[i]));
  }

  // Parser does not handle AssetLevy type. Let say transaction contains Levy if data packet is not empty.
  const uint8_t *ptr;
  size_t len;
  PARSER_CHK(parse_data(parser, &ptr, &len));
  asset_definition->has_levy = (len != 0);
  return 0;
}

static int parse_asset_supply_type(Parser *parser, enum AssetSupplyType *supply_type) {
  uint32_t type;

  PARSER_CHK(parse_u32(parser, &type));
  if (type != AssetSupplyIncrease && type != AssetSupplyDecrease) {
    return -1;
  }
  *supply_type = type;
  return 0;
}

static int parse_transaction_type(Parser *parser, TransactionType *type) {
  const TransactionType allowed_types[] = {
      TransferType, ImportanceTransferType, MultisigAggregateModificationType, MultisigSignatureType,
      MultisigType, ProvisionNamespaceType, MosaicDefinitionCreationType, MosaicSupplyChangeType
  };
  PARSER_CHK(parse_u32(parser, type));
  for (size_t i = 0; i < sizeof(allowed_types) / sizeof(allowed_types[0]); i++) {
    if (allowed_types[i] == *type) {
      return 0;
    }
  }
  return -1;
}

int parse_transaction_header(Parser *parser, TransactionHeader *header) {
  PARSER_CHK(parse_transaction_type(parser, &header->type));
  PARSER_CHK(parse_version_and_network(parser, &header->version, &header->network));
  PARSER_CHK(parse_u32(parser, &header->timestamp));
  PARSER_CHK(parse_account(parser, &header->signer));
  PARSER_CHK(parse_u64(parser, &header->fee));
  PARSER_CHK(parse_u32(parser, &header->deadline));
  return 0;
}

int parse_transfer_transaction(Parser *parser, TransferTransaction *transaction, TransactionHeader *header) {
  PARSER_CHK(parse_address(parser, &transaction->recipient));
  PARSER_CHK(parse_u64(parser, &transaction->amount));
  PARSER_CHK(parse_message(parser, &transaction->message));

  if (header->version == Version2) {
    PARSER_CHK(parse_u32(parser, &transaction->num_assets));
    if (transaction->num_assets > ASSETS_NUM) {
      return -1;
    }
    for (int i = 0; i < transaction->num_assets; i++) {
      Parser asset_parser;
      PARSER_CHK(parse_data(parser, &asset_parser.buffer, &asset_parser.buffer_length));
      PARSER_CHK(parse_asset(&asset_parser, &transaction->assets[i]));
    }
  } else {
    transaction->num_assets = 0;
  }
  return 0;
}

int parse_importance_transfer_transaction(Parser *parser,
                                          ImportanceTransferTransaction *transaction,
                                          TransactionHeader *header) {
  (void) header;

  uint32_t mode;
  PARSER_CHK(parse_u32(parser, &mode));
  if (mode != ImportanceModeActivate && mode != ImportanceModeDeactivate) {
    return -1;
  }
  transaction->mode = mode;
  PARSER_CHK(parse_account(parser, &transaction->remote_account));
  return 0;
}

static int parse_cosignatory_modification(Parser *parser, CosignatoryModification *modification) {
  uint32_t action;
  PARSER_CHK(parse_u32(parser, &action));
  if (action != ActionAdd && action != ActionDelete) {
    return -1;
  }
  modification->action = action;

  PARSER_CHK(parse_account(parser, &modification->cosignatory_account));
  return 0;
}

int parse_multisig_aggregate_modification_transaction(Parser *parser,
                                                      MultisigAggregateModificationTransaction *transaction,
                                                      struct TransactionHeader *header) {
  PARSER_CHK(parse_u32(parser, &transaction->num_modifications));
  if (transaction->num_modifications > MAX_MODIFICATIONS) {
    return -1;
  }
  for (int i = 0; i < transaction->num_modifications; i++) {
    Parser mod_parser;

    PARSER_CHK(parse_data(parser, &mod_parser.buffer, &mod_parser.buffer_length));
    PARSER_CHK(parse_cosignatory_modification(&mod_parser, &transaction->modifications[i]));
    if (mod_parser.buffer_length != 0) {
      return -1;
    }
  }

  if (header->version == Version2) {
    // Version 2 includes "minCosignatories", which have one entry: "relativeChange".
    Parser cosig_parser;

    PARSER_CHK(parse_data(parser, &cosig_parser.buffer, &cosig_parser.buffer_length));
    PARSER_CHK(parse_u32(&cosig_parser, &transaction->relative_change));
    if (cosig_parser.buffer_length != 0) {
      return -1;
    }
  }
  return 0;
}

int parse_multisig_signature_transaction(Parser *parser,
                                         MultisigSignatureTransaction *transaction,
                                         TransactionHeader *header) {
  (void) header;

  Parser hash_parser;
  PARSER_CHK(parse_data(parser, &hash_parser.buffer, &hash_parser.buffer_length));
  PARSER_CHK(parse_hash(&hash_parser, &transaction->other_hash));
  if (hash_parser.buffer_length != 0) {
    return -1;
  }
  PARSER_CHK(parse_address(parser, &transaction->other_account));
  return 0;
}

int parse_multisig_transaction(Parser *parser, MultisigTransaction *transaction, TransactionHeader *header) {
  (void) header;

  Parser tx_parser;
  PARSER_CHK(parse_data(parser, &tx_parser.buffer, &tx_parser.buffer_length));

  // Parse inner transaction
  PARSER_CHK(parse_transaction_header(&tx_parser, &transaction->header));

  switch (transaction->header.type) {
  case TransferType:
    PARSER_CHK(parse_transfer_transaction(&tx_parser, &transaction->transfer, &transaction->header));
    break;
  case ImportanceTransferType:
    PARSER_CHK(parse_importance_transfer_transaction(
        &tx_parser,
        &transaction->importance_transfer,
        &transaction->header));
    break;
  case MultisigAggregateModificationType:
    PARSER_CHK(parse_multisig_aggregate_modification_transaction(
        &tx_parser,
        &transaction->multisig_aggregated_modification,
        &transaction->header));
    break;
  case ProvisionNamespaceType:
    PARSER_CHK(parse_provision_namespace_transaction(
        &tx_parser,
        &transaction->provision_namespace,
        &transaction->header));
    break;
  case MosaicDefinitionCreationType:
    PARSER_CHK(parse_mosaic_definition_creation_transaction(
        &tx_parser,
        &transaction->mosaic_definition_creation,
        &transaction->header));
    break;
  case MosaicSupplyChangeType:
    PARSER_CHK(parse_mosaic_supply_change_transaction(
        &tx_parser,
        &transaction->mosaic_supply_change,
        &transaction->header));
    break;
  default:
    return -1;
  }
  // No additional data after inner transaction
  if (tx_parser.buffer_length != 0) {
    return -1;
  }
  return 0;
}

int parse_provision_namespace_transaction(Parser *parser,
                                          ProvisionNamespaceTransaction *transaction,
                                          TransactionHeader *header) {
  (void) header;

  PARSER_CHK(parse_address(parser, &transaction->rental_fee_sink));
  PARSER_CHK(parse_u64(parser, &transaction->rental_fee));
  PARSER_CHK(parse_sized_string(parser, &transaction->new_part));
  PARSER_CHK(parse_sized_string(parser, &transaction->parent));
  return 0;
}

int parse_mosaic_definition_creation_transaction(Parser *parser,
                                                 AssetDefinitionCreationTransaction *transaction,
                                                 TransactionHeader *header) {
  (void) header;

  Parser asset_parser;
  PARSER_CHK(parse_data(parser, &asset_parser.buffer, &asset_parser.buffer_length));
  PARSER_CHK(parse_asset_definition(&asset_parser, &transaction->asset_definition));
  if (asset_parser.buffer_length != 0) {
    return -1;
  }
  PARSER_CHK(parse_address(parser, &transaction->creation_fee_sink));
  PARSER_CHK(parse_u64(parser, &transaction->creation_fee));
  return 0;
}

int parse_mosaic_supply_change_transaction(Parser *parser,
                                           MosaicSupplyChangeTransaction *transaction,
                                           TransactionHeader *header) {
  (void) header;

  // FIXME: there is no test for this kind of message
  PARSER_CHK(parse_asset_id(parser, &transaction->id));
  PARSER_CHK(parse_asset_supply_type(parser, &transaction->supply_type));
  PARSER_CHK(parse_u64(parser, &transaction->delta));
  return 0;
}

#ifdef UNITTEST

#include <setjmp.h>
#include <stdarg.h>
#include "cmocka.h"

static void test_parse_u32(void **state) {
  (void) state;

  uint8_t input_data[] = {0x11, 0x22, 0x33, 0x44};
  Parser parser = { input_data, sizeof(input_data)};
  uint32_t n;

  assert_int_equal(parse_u32(&parser, &n), 0);
  assert_int_equal(n, 0x44332211);

  Parser parser2 = { input_data, sizeof(input_data) - 1};  // buffer too small
  assert_int_not_equal(parse_u32(&parser2, &n), 0);
}

static void test_parse_version_and_network(void **state) {
  (void) state;

  uint8_t input_data[] = {0x01, 0x00, 0x00, 0x98};
  Parser parser = { input_data, sizeof(input_data)};
  Network network;
  Version version;

  assert_int_equal(parse_version_and_network(&parser, &version, &network), 0);
  assert_int_equal(version, Version1);
  assert_int_equal(network, NetworkTestnet);
}

int main() {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_parse_u32),
      cmocka_unit_test(test_parse_version_and_network),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);
}
#endif
