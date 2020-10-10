/*******************************************************************************
*    NEM Wallet
*    (c) 2020 FDS
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/

#include "nem_parse.h"
#include "apdu/global.h"
#include "nem/format/readers.h"

#pragma pack(push, 1)

#define STRUCT_ADDRESS_LENGTH 44
typedef struct address_t {
    uint32_t length;
    uint8_t address[NEM_ADDRESS_LENGTH];
} address_t;

#define STRUCT_PUBLICKEY_LENGTH 36
typedef struct publickey_t {
    uint32_t length;
    uint8_t publicKey[NEM_PUBLIC_KEY_LENGTH];
} publickey_t;

#define TRANSFER_TXN_HEADER_LENGTH           56
typedef struct transfer_txn_header_t {
    address_t recipient; //44
    uint64_t amount; // 8
    uint32_t messageLength;
} transfer_txn_header_t;

#define IMPORTANCE_TRANSFER_TXN_HEADER_LENGTH 40
typedef struct importance_txn_header_t {
    uint32_t importanceMode;
    publickey_t iPublicKey;
} importance_txn_header_t;

#define AGGREGATE_MODIFICATION_HEADER_LENGTH    44
typedef struct aggregate_modication_header_t {
    uint32_t cosignatoryModificationLength;
    uint32_t modicationType;
    publickey_t amPublicKey;
} aggregate_modication_header_t;

#define MULTISIG_SIGNATURE_HEADER_LENGTH        84

typedef struct multsig_signature_header_t {
    uint32_t hashObjectLength;
    uint32_t hashLength;
    uint8_t hash[NEM_TRANSACTION_HASH_LENGTH];
    address_t msAddress;
} multsig_signature_header_t;

#define COSIGNATORIES_MODIFICATION_HEADER_LENGTH  8
typedef struct cosignatories_modification_header_t {
    uint32_t minCosignatoriesModification;
    uint32_t relativeChange;
} cosignatories_modification_header_t;

#define RENTAL_HEADER_LENGTH    52
typedef struct rental_header_t {
    address_t rAddress;
    uint64_t rentalFee;
} rental_header_t;

#define MOSAIC_DEFINITION_CREATION_HEADER_LENGTH    48
typedef struct mosaic_definition_creation_t {
    uint32_t defStructLen;
    publickey_t mdcPublicKey;
    uint32_t idStructLength;
    uint32_t nsIdLen;
} mosaic_definition_creation_t;

#define LEVY_STRUCTURE_HEADER_LENGTH            56
typedef struct levy_structure_t {
    uint32_t feeType;
    address_t lsAddress;
    uint32_t msIdLen;
    uint32_t nsIdLen;
} levy_structure_t;

#define MOSAIC_DEFINITION_SINK_HEADER_LENGTH          52
typedef struct mosaic_definition_sink_t {
    address_t mdAddress;
    uint64_t fee;
} mosaic_definition_sink_t;

typedef struct version_t {
    uint8_t ver;
    uint8_t reserve[2];
    uint8_t networkType;
} version_t;

#define COMMON_TX_HEADER_LENGTH             60
typedef struct common_txn_header_t {
    uint32_t transactionType;
    //version_t version;
    uint8_t version;
    uint16_t reserve;
    uint8_t networkType;
    uint32_t timestamp;
    publickey_t publicKey;
    uint64_t fee;
    uint32_t deadline;
} common_txn_header_t;

#pragma pack(pop)

bool has_data(parse_context_t *context, uint32_t numBytes) {
    return context->offset + numBytes - 1 < context->length;
}

field_t *get_field(parse_context_t *context, int idx) {
    return &context->result.fields[idx];
}

field_t* _set_field_data(field_t* field, uint8_t id, uint8_t data_type, uint16_t length, uint8_t* data) {
    field->id = id;
    field->dataType = data_type;
    field->length = length;
    field->data = data;
    return field;
}

field_t* set_field_data(parse_context_t *context, int idx, uint8_t id, uint8_t data_type, uint16_t length, uint8_t* data) {
    return _set_field_data(get_field(context, idx), id, data_type, length, data);
}

field_t *add_new_field(parse_context_t *context, uint8_t id, uint8_t data_type, uint16_t length, uint8_t* data) {
    return set_field_data(context, context->result.numFields++, id, data_type, length, data);
}

uint8_t* read_data(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) {
        uint32_t offset = context->offset;
        context->offset += numBytes;
        PRINTF("******* Read: %d bytes - Move offset: %d->%d/%d\n", numBytes, offset, context->offset, context->length);
        return context->data + offset;
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

uint32_t _read_uint32(parse_context_t *context) {
    return read_uint32(read_data(context, sizeof(uint32_t)));
}

uint8_t _read_uint8(parse_context_t *context) {
    return read_uint8(read_data(context, sizeof(uint8_t)));
}

void move_position(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) {
        context->offset += numBytes;
        PRINTF("******* Move: %d bytes - Move offset: %d->%d/%d\n", numBytes, context->offset-numBytes, context->offset, context->length);
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

uint8_t get_nem_version(common_txn_header_t *common_header) {
    // version_t *version = (version_t*)&common_header->version;
    // return version->ver;
    // return common_header->version[0];
    return common_header->version;
}

void parse_transfer_txn_content(parse_context_t *context, common_txn_header_t *common_header) {
    transfer_txn_header_t *txn = (transfer_txn_header_t *) read_data(context, TRANSFER_TXN_HEADER_LENGTH);
    // address_t *recipient  = (address_t *) read_data(context, STRUCT_ADDRESS_LENGTH);
    char str[32];
    uint8_t *ptr;
    // Show Recipient address
    add_new_field(context, NEM_STR_RECIPIENT_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &txn->recipient.address);
    uint8_t *pamount = (uint8_t *) &txn->amount; //read_data(context, sizeof(uint64_t));
    uint32_t messageLength = txn->messageLength; //_read_uint32(context);
    // sprintf_number(str, 32, txn->amount);
    PRINTF("sizeof = %d xem\n", sizeof(transfer_txn_header_t));
    if (messageLength == 0) {
        // empty msg
        add_new_field(context, NEM_STR_TXN_MESSAGE, STI_MESSAGE, 0, NULL);
    } else {
        uint32_t payloadType = _read_uint32(context);
        uint32_t payloadLength = _read_uint32(context);
        if (payloadType == 1) {
            // Show Message
            add_new_field(context, NEM_STR_TXN_MESSAGE, STI_MESSAGE, payloadLength, read_data(context, payloadLength));
        } else { //show <encrypted msg>
            add_new_field(context, NEM_STR_ENC_MESSAGE, STI_MESSAGE, 0, NULL);
        }
    }
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
    if (common_header->version == 1) { // NEM1
        // Show xem amount
        add_new_field(context, NEM_MOSAIC_AMOUNT, STI_NEM, sizeof(uint64_t), (uint8_t*) pamount);
    } else if (common_header->version == 2) { //NEM2
        // num of mosaic pointer
        ptr = read_data(context, sizeof(uint32_t));
        uint32_t numMosaic = read_uint32(ptr);
        if (numMosaic == 0) {
            // Show xem amount
            add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) pamount);
        } else {
            // Show sent other mosaic num
            add_new_field(context, NEM_UINT32_MOSAIC_COUNT, STI_UINT32, sizeof(uint32_t), ptr);
            for (uint32_t i = 0; i < numMosaic; i++) {
                // mosaic structure length pointer
                ptr = read_data(context, sizeof(uint32_t));
                // mosaicId structure length pointer
                ptr = read_data(context, sizeof(uint32_t));
                // namespaceID length pointer
                ptr = read_data(context, sizeof(uint32_t));
                uint32_t nsIdLen = read_uint32(ptr);
                // namespaceID pointer
                ptr = read_data(context, nsIdLen);
                sprintf_ascii(str, 32, ptr, nsIdLen);
                PRINTF("namespaceId=%s\n", str);
                uint8_t is_nem = 0; //namespace is nem
                if (strcmp(str, "nem") == 0) {
                    is_nem = 1;
                }
                // mosaic name length pointer
                ptr = read_data(context, sizeof(uint32_t));
                uint32_t mosaicNameLen = read_uint32(ptr);
                // mosaic name and quantity
                ptr = read_data(context, mosaicNameLen + sizeof(uint64_t));
                sprintf_ascii(str, 32, ptr, mosaicNameLen);
                PRINTF("mosaicName=%s\n", str);
                if (is_nem == 1 && strcmp(str, "xem") == 0) {
                    // xem quantity
                    add_new_field(context, NEM_MOSAIC_AMOUNT, STI_NEM, sizeof(uint64_t), (uint8_t *)(ptr + mosaicNameLen));
                } else {
                    // mosaic name and quantity
                    add_new_field(context, NEM_MOSAIC_UNITS, STI_MOSAIC_CURRENCY, mosaicNameLen + sizeof(uint64_t), ptr);
                }
            }
        }
    }
}

void parse_importance_tranfer_txn_content(parse_context_t *context, common_txn_header_t *common_header) {
    importance_txn_header_t *txn = (importance_txn_header_t*) read_data(context, IMPORTANCE_TRANSFER_TXN_HEADER_LENGTH);
    //  Show importance transfer mode
    add_new_field(context, NEM_UINT32_IT_MODE, STI_UINT32, sizeof(uint8_t), (uint8_t*) &txn->importanceMode);
    // Show public key of remote account
    add_new_field(context, NEM_PUBLICKEY_IT_REMOTE, STI_HASH256, NEM_PUBLIC_KEY_LENGTH, (uint8_t*) &txn->iPublicKey.publicKey);
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
}

void parse_aggregate_modification_txn_content(parse_context_t *context, common_txn_header_t *common_header) {
    uint8_t *ptr = read_data(context, sizeof(uint32_t));
    uint32_t cosignatoriesModificationNum = read_uint32(ptr);
    // Show number of cosignatory modification
    add_new_field(context, NEM_UINT32_AM_COSIGNATORY_NUM, STI_UINT32, sizeof(uint32_t), ptr);
    for (uint32_t i = 0; i < cosignatoriesModificationNum; i++) {
        aggregate_modication_header_t *txn = (aggregate_modication_header_t*) read_data(context, AGGREGATE_MODIFICATION_HEADER_LENGTH);
        //  Show modification type
        add_new_field(context, NEM_UINT32_AM_MODICATION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &txn->modicationType);
        // Show public key of cosignatory
        add_new_field(context, NEM_PUBLICKEY_AM_COSIGNATORY, STI_HASH256, NEM_PUBLIC_KEY_LENGTH, (uint8_t*) &txn->amPublicKey.publicKey);
    }
    if (common_header->version == 2) {
        ptr = read_data(context, sizeof(uint32_t));
        uint32_t cosignaturiesModificationStructureLength = read_uint32(ptr);
        if (cosignaturiesModificationStructureLength > 0) {
            // Show relative change in minimum cosignatories modification structure
            add_new_field(context, NEM_UINT32_AM_RELATIVE_CHANGE, STI_UINT32, sizeof(uint32_t), read_data(context, sizeof(uint32_t)));
        } else {
            // Show no minimum cosignatories modification
            add_new_field(context, NEM_UINT32_AM_RELATIVE_CHANGE, STI_UINT32, sizeof(uint32_t), ptr);
        }
    }
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
}

void parse_multisig_signature_txn_context(parse_context_t *context, common_txn_header_t *common_header) {
    multsig_signature_header_t *txn = (multsig_signature_header_t*) read_data(context, MULTISIG_SIGNATURE_HEADER_LENGTH);
    // Show sha3 hash
    add_new_field(context, NEM_HASH256, STI_HASH256, txn->hashLength, (uint8_t*) txn->hash);
    // Show multisig address
    add_new_field(context, NEM_STR_MULTISIG_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &txn->msAddress.address);
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
}

void parse_provision_namespace_txn_content(parse_context_t *context, common_txn_header_t *common_header) {
    rental_header_t *txn = (rental_header_t*) read_data(context, RENTAL_HEADER_LENGTH);
    // Show sink address
    add_new_field(context, NEM_STR_SINK_ADDRESS, STI_ADDRESS, txn->rAddress.length, (uint8_t*) &txn->rAddress.address);
    // Show rental fee
    add_new_field(context, NEM_UINT64_RENTAL_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &txn->rentalFee);
    uint32_t len = _read_uint32(context);
    // New part string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
    len = _read_uint32(context);
    if (len != -1) {
        // Parent string
        add_new_field(context, NEM_STR_PARENT_NAMESPACE, STI_STR, len, read_data(context, len));
    }
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
}

void parse_mosaic_definition_creation_txn_content(parse_context_t *context, common_txn_header_t *common_header) {
    mosaic_definition_creation_t *txn = (mosaic_definition_creation_t*) read_data(context, MOSAIC_DEFINITION_CREATION_HEADER_LENGTH);
    uint8_t *ptr;
    // Show namespace id string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, txn->nsIdLen, read_data(context, txn->nsIdLen));
    uint32_t len = read_uint32(read_data(context, sizeof(uint32_t)));
    // Show mosaic name string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
    len = read_uint32(read_data(context, sizeof(uint32_t)));
    // Show description string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
    uint32_t propertyNum = _read_uint32(context);
    for (uint32_t i = 0; i < propertyNum; i++) {
        // Property structure length
        ptr = read_data(context, sizeof(uint32_t));
        len = _read_uint32(context);
        // Show property name string
        add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
        len = _read_uint32(context);
        // Show property value string
        add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
    }
    // Levy structure length
    len = _read_uint32(context);
    if(len > 0) {
        levy_structure_t *levy = (levy_structure_t*) read_data(context, LEVY_STRUCTURE_HEADER_LENGTH);
        // Show fee type
        add_new_field(context, NEM_UINT32_AM_MODICATION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &levy->feeType);
        // Show recipient address
        add_new_field(context, NEM_STR_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &levy->lsAddress.address);
        // Show namespace name string
        add_new_field(context, NEM_STR_NAMESPACE, STI_STR, levy->nsIdLen, read_data(context, levy->nsIdLen));
        len = _read_uint32(context);
        // Show namespace name string
        add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
        // Show levy fee
        add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), read_data(context, sizeof(uint64_t)));
    }
    mosaic_definition_sink_t *sink = (mosaic_definition_sink_t*) read_data(context, MOSAIC_DEFINITION_SINK_HEADER_LENGTH);
    // Show sink address
    add_new_field(context, NEM_STR_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &sink->mdAddress.address);
    // Show sink fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &sink->fee);
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
}

void parse_mosaic_supply_change_txn_content(parse_context_t *context, common_txn_header_t *common_header) {
    // move offset to 4 bytes
    move_position(context, sizeof(uint32_t));
    uint32_t len = _read_uint32(context);
    // Show namespace id string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
    len = _read_uint32(context);
    // Show mosaic name string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, read_data(context, len));
    len = _read_uint32(context);
    // Show supply type string
    add_new_field(context, NEM_UINT32_MSC_TYPE, STI_UINT32, sizeof(uint32_t), read_data(context, sizeof(uint32_t)));
    // Show delta change
    add_new_field(context, NEM_UINT64_MSC_AMOUNT, STI_UINT64, sizeof(uint64_t), read_data(context, sizeof(uint64_t)));
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
}

void parse_inner_txn_content(parse_context_t *context, uint32_t len) {
    uint32_t totalSize = 0;
    while (totalSize < len) {
        uint32_t previousOffset = context->offset;
        // get header first
        common_txn_header_t *txn = (common_txn_header_t*) read_data(context, COMMON_TX_HEADER_LENGTH);
        // Show inner transaction type
        add_new_field(context, NEM_UINT32_INNER_TRANSACTION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &txn->transactionType);
        switch (txn->transactionType) {
            case NEM_TXN_TRANSFER:
                parse_transfer_txn_content(context, txn);
                break;
            case NEM_TXN_IMPORTANCE_TRANSFER:
                parse_importance_tranfer_txn_content(context, txn);
                break;
            case NEM_TXN_MULTISIG_AGGREGATE_MODIFICATION:
                parse_aggregate_modification_txn_content(context, txn);
                break;
            case NEM_TXN_MULTISIG_SIGNATURE:
                parse_multisig_signature_txn_context(context, txn);
                break;
            case NEM_TXN_PROVISION_NAMESPACE:
                parse_provision_namespace_txn_content(context, txn);
                break;
            case NEM_TXN_MOSAIC_DEFINITION:
                parse_mosaic_definition_creation_txn_content(context, txn);
                break;
            case NEM_TXN_MOSAIC_SUPPLY_CHANGE:
                parse_mosaic_supply_change_txn_content(context, txn);
                break;
            default:
                break;
        }
        totalSize = totalSize + context->offset - previousOffset;
    }
}

void parse_multisig_txn_context(parse_context_t *context, common_txn_header_t *common_header) {
    uint32_t innerTxnLength = read_uint32(read_data(context, sizeof(uint32_t)));
    if (has_data(context, innerTxnLength)) {
        parse_inner_txn_content(context, innerTxnLength);
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void parse_txn_detail(parse_context_t *context, common_txn_header_t *txn) {
    PRINTF("Parse tc detail\n");
    context->result.numFields = 0;
    PRINTF("%x\n%x", txn->transactionType, txn->fee);
    for(uint8_t i =0; i < 20; i++) {
        PRINTF("%02x", *(&context->data + context->offset + i));
    }
    // Show Transaction type
    add_new_field(context, NEM_UINT32_TRANSACTION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &txn->transactionType);
    PRINTF("\nParse tx detail before switch\n");
    switch (txn->transactionType) {
        case NEM_TXN_TRANSFER:
            parse_transfer_txn_content(context, txn);
            break;
        case NEM_TXN_IMPORTANCE_TRANSFER:
            parse_importance_tranfer_txn_content(context, txn);
            break;
        case NEM_TXN_MULTISIG_AGGREGATE_MODIFICATION:
            parse_aggregate_modification_txn_content(context, txn);
            break;
        case NEM_TXN_MULTISIG_SIGNATURE:
            parse_multisig_signature_txn_context(context, txn);
            break;
        case NEM_TXN_MULTISIG:
            parse_multisig_txn_context(context, txn);
            break;
        case NEM_TXN_PROVISION_NAMESPACE:
            parse_provision_namespace_txn_content(context, txn);
            break;
        case NEM_TXN_MOSAIC_DEFINITION:
            parse_mosaic_definition_creation_txn_content(context, txn);
            break;
        case NEM_TXN_MOSAIC_SUPPLY_CHANGE:
            parse_mosaic_supply_change_txn_content(context, txn);
            break;
        default:
            // Mask real cause behind generic error (INCORRECT_DATA)
            THROW(0x6A80);
            break;
    }
}

common_txn_header_t *parse_common_txn_header_t(parse_context_t *context) {
    // get gen_hash and transaction_type
    common_txn_header_t *common_header = (common_txn_header_t *) read_data(context, sizeof(common_txn_header_t));
    context->version = common_header->version;
    PRINTF("NEM Version %d\n", context->version);
    return common_header;
}

void parse_txn_internal(parse_context_t *context) {
    common_txn_header_t* txn = parse_common_txn_header_t(context);
    parse_txn_detail(context, txn);
}

void parse_txn_context(parse_context_t *context) {
    BEGIN_TRY {
        TRY {
            parse_txn_internal(context);
        }
        CATCH_OTHER(e) {
            switch (e & 0xF000u) {
                case 0x6000:
                    // Proper error, forward it further
                    THROW(e);
                default:
                    // Mask real cause behind generic error (INCORRECT_DATA)
                    THROW(0x6A80);
            }
        }
        FINALLY {
        }
    }
    END_TRY
}
