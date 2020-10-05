#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ACCOUNT_SIZE 32
#define ADDRESS_SIZE 40
#define HASH_SIZE 32

typedef int8_t Address[ADDRESS_SIZE];
typedef uint8_t Account[ACCOUNT_SIZE];

typedef enum Version {
  Version1=1,
  Version2=2
} Version;

typedef enum Network {
  NetworkMainnet=0x68,
  NetworkTestnet=0x98
} Network;

enum MessageType {
  MessageNone,
  MessagePlain=1,
  MessageEncrypted=2,
};

typedef struct HashData {
  uint8_t data[HASH_SIZE];
} HashData;

typedef struct Data {
  size_t length;
  const uint8_t *data;
} Data;

typedef struct SizedString {
  size_t length;
  const char* string;
} SizedString;

typedef struct Message {
  enum MessageType type;
  union {
    SizedString plain;
    Data encrypted;
  };
} Message;

#define ASSET_PROPERTIES_NUM 4

typedef struct AssetProperty {
  SizedString name;
  SizedString value;
} AssetProperty;

typedef struct AssetId {
  SizedString namespace_id;
  SizedString name;
} AssetId;

#define ASSETS_NUM 4  // Arbitrary value

typedef struct Asset {
  AssetId asset_id;
  uint64_t quantity;
} Asset;

typedef struct AssetDefinition {
  const Account *creator;
  AssetId id;
  SizedString description;
  AssetProperty properties[ASSET_PROPERTIES_NUM];
  bool has_levy;
} AssetDefinition;

enum AssetSupplyType {
  AssetSupplyIncrease = 1,
  AssetSupplyDecrease = 2,
};

typedef enum TransactionType {
  TransferType=0x101,
  ImportanceTransferType=0x801,
  MultisigAggregateModificationType=0x1001,
  MultisigSignatureType=0x1002,
  MultisigType=0x1004,
  ProvisionNamespaceType=0x2001,
  MosaicDefinitionCreationType=0x4001,
  MosaicSupplyChangeType=0x4002
} TransactionType;

typedef struct TransactionHeader {
  TransactionType type;
  Version version;
  Network network;
  uint32_t timestamp;
  const Account *signer;
  uint64_t fee;
  uint32_t deadline;
} TransactionHeader;

typedef struct TransferTransaction {
  const Address *recipient;
  uint64_t amount;
  Message message;
  uint32_t num_assets;
  Asset assets[ASSETS_NUM];
} TransferTransaction;


enum ImportanceMode {
  ImportanceModeActivate = 1,
  ImportanceModeDeactivate = 2
};

typedef struct ImportanceTransferTransaction {
  enum ImportanceMode mode;
  const Account *remote_account;
} ImportanceTransferTransaction;

#define MAX_MODIFICATIONS 5

enum CosignatoryModificationAction {
  ActionAdd = 1,
  ActionDelete = 2
};

typedef struct CosignatoryModification {
  const Account *cosignatory_account;
  enum CosignatoryModificationAction action;
} CosignatoryModification;

typedef struct MultisigAggregateModificationTransaction {
  uint32_t num_modifications;
  CosignatoryModification modifications[MAX_MODIFICATIONS];
  uint32_t relative_change;
} MultisigAggregateModificationTransaction;

typedef struct MosaicSupplyChangeTransaction {
  AssetId id;
  enum AssetSupplyType supply_type;
  uint64_t delta;
} MosaicSupplyChangeTransaction;

typedef struct ProvisionNamespaceTransaction {
  const Address *rental_fee_sink;
  uint64_t rental_fee;
  SizedString new_part;
  SizedString parent;
} ProvisionNamespaceTransaction;

typedef struct AssetDefinitionCreationTransaction {
  AssetDefinition asset_definition;
  const Address *creation_fee_sink;
  uint64_t creation_fee;
} AssetDefinitionCreationTransaction;

typedef struct MultisigTransaction {
  TransactionHeader header;
  union {
    TransferTransaction transfer;
    ImportanceTransferTransaction importance_transfer;
    MultisigAggregateModificationTransaction multisig_aggregated_modification;
    ProvisionNamespaceTransaction provision_namespace;
    AssetDefinitionCreationTransaction mosaic_definition_creation;
    MosaicSupplyChangeTransaction mosaic_supply_change;
  };
} MultisigTransaction;

typedef struct MultisigSignatureTransaction {
  const HashData *other_hash;
  const Address *other_account;
} MultisigSignatureTransaction;

