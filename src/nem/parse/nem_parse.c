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

typedef struct address_t {
    //Length of address (always 40)
    uint32_t length;
    //Address: 40 bytes (using UTF8 encoding).
    uint8_t address[NEM_ADDRESS_LENGTH];
} address_t;

typedef struct publickey_t {
    //Length of public key byte array (always 32)
    uint32_t length;
    //Public key bytes: 32 bytes.
    uint8_t publicKey[NEM_PUBLIC_KEY_LENGTH];
} publickey_t;

typedef struct transfer_txn_header_t {
    address_t recipient;
    //Amount (micro nem)
    uint64_t amount;
    //Length of message
    uint32_t msgLen;
} transfer_txn_header_t;

typedef struct importance_txn_header_t {
    //Importance transfer mode. The following modes are supported: 0x01 (Activate), 0x02 (Deactivate)
    uint32_t iMode;
    publickey_t iPublicKey;
} importance_txn_header_t;

typedef struct aggregate_modication_header_t {
    //Length of cosignatory modification structure
    uint32_t cmsLen;
    //Modification type
    uint32_t amType;
    publickey_t amPublicKey;
} aggregate_modication_header_t;

typedef struct multsig_signature_header_t {
    //Length of hash object (hash of the corresponding multisig transaction
    uint32_t hashObjLen;
    //Length of hash
    uint32_t hashLen;
    //SHA3 hash bytes: 32 bytes
    uint8_t hash[NEM_TRANSACTION_HASH_LENGTH];
    //Multisig account address (using UTF8 encoding)
    address_t msAddress;
} multsig_signature_header_t;

typedef struct rental_header_t {
    //Address bytes of rental fee sink
    address_t rAddress;
    //Rental fee (Root always: 100000000, Sub always: 10000000) for namespace
    uint64_t rentalFee;
} rental_header_t;

typedef struct mosaic_definition_creation_t {
    //Length of mosaic definition structure
    uint32_t defStructLen;
    //Public keyof creator
    publickey_t mdcPublicKey;
    //Length of mosaic id structure
    uint32_t idStructLen;
    //Length of namespace id string
    uint32_t nsIdLen;
} mosaic_definition_creation_t;

typedef struct levy_structure_t {
    //Fee type: The following fee types are supported. 0x01 (absolute fee), 0x02 (percentile fee)
    uint32_t feeType;
    address_t lsAddress;
    //Length of mosaic id structure
    uint32_t msIdLen;
} levy_structure_t;

typedef struct mosaic_definition_sink_t {
    address_t mdAddress;
    uint64_t fee;
} mosaic_definition_sink_t;

typedef struct common_txn_header_t {
    //transaction type
    uint32_t transactionType;
    //nem version: 1 or 2
    uint8_t version;
    uint16_t reserve;
    //network type: mainnet, testnet
    uint8_t networkType;
    uint32_t timestamp;
    publickey_t publicKey;
    uint64_t fee;
    uint32_t deadline;
} common_txn_header_t;

#pragma pack(pop)

#define BAIL_IF(x) {int err = x; if (err) return err;}

// Security check
static bool has_data(parse_context_t *context, uint32_t numBytes) {
    if (context->offset + numBytes < context->offset) {
        return false;
    }
    return context->offset + numBytes - 1 < context->length;
}

static field_t *get_field(parse_context_t *context, int idx) {
    return &context->result.fields[idx];
}

static int _set_field_data(field_t* field, uint8_t id, uint8_t data_type, uint16_t length, const uint8_t* data) {
    field->id = id;
    field->dataType = data_type;
    field->length = length;
    field->data = data;
    return 0;
}

static int set_field_data(parse_context_t *context, int idx, uint8_t id, uint8_t data_type, uint16_t length, const uint8_t* data) {
    if (idx >= MAX_FIELD_COUNT) {
        return E_TOO_MANY_FIELDS;
    }
    return _set_field_data(get_field(context, idx), id, data_type, length, data);
}

static int add_new_field(parse_context_t *context, uint8_t id, uint8_t data_type, uint16_t length, const uint8_t* data) {
    return set_field_data(context, context->result.numFields++, id, data_type, length, data);
}

// Read data and security check
static const uint8_t* read_data(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) { // Security check
        uint32_t offset = context->offset;
        context->offset += numBytes;
        // PRINTF("******* Read: %d bytes - Move offset: %d->%d/%d\n", numBytes, offset, context->offset, context->length);
        return context->data + offset;
    } else {
        return NULL;
    }
}

// Read uint32 and security check
static int _read_uint32(parse_context_t *context, uint32_t *result) {
    const uint8_t *p = read_data(context, sizeof(uint32_t));
    if (p) {
        *result = read_uint32(p);
        return 0;
    }
    return E_NOT_ENOUGH_DATA;
}

// Move position and security check
static const uint8_t* move_pos(parse_context_t *context, uint32_t numBytes) {
    return read_data(context, numBytes); // Read data and security check
}

static int parse_transfer_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    transfer_txn_header_t *txn = (transfer_txn_header_t *) read_data(context, sizeof(transfer_txn_header_t)); // Read data and security check
    char str[32];
    const uint8_t *ptr;

    if (txn == NULL) {
        return E_NOT_ENOUGH_DATA;
    }

    // Show Recipient address
    BAIL_IF(add_new_field(context, NEM_STR_RECIPIENT_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &txn->recipient.address));
    if (common_header->version == 1) { // NEM tranfer tx version 1
        // Show xem amount
        add_new_field(context, NEM_MOSAIC_AMOUNT, STI_NEM, sizeof(uint64_t), (uint8_t*) &txn->amount);
    }
    if (txn->msgLen == 0) {
        // empty msg
        add_new_field(context, NEM_STR_TXN_MESSAGE, STI_MESSAGE, 0, NULL);
    } else {
        uint32_t payloadType, payloadLength;
        if (_read_uint32(context, &payloadType)) {
            return E_NOT_ENOUGH_DATA;
        }
        if (_read_uint32(context, &payloadLength)) {
            return E_NOT_ENOUGH_DATA;
        }
        if (payloadType == 1) {
            // Show Message
            ptr = read_data(context, payloadLength);
            if (ptr == NULL) {
                return E_NOT_ENOUGH_DATA;
            }
            add_new_field(context, NEM_STR_TXN_MESSAGE, STI_MESSAGE, payloadLength, ptr); // Read data and security check
        } else { //show <encrypted msg>
            add_new_field(context, NEM_STR_ENC_MESSAGE, STI_MESSAGE, 0, NULL);
        }
    }
    // Show fee
    BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee));
    if (common_header->version == 2) { //NEM tranfer tx version 2
        // num of mosaic pointer
        uint32_t numMosaic;
        BAIL_IF(_read_uint32(context, &numMosaic));
        if (numMosaic == 0) {
            // Show xem amount
            BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &txn->amount));
        } else {
            // Show sent other mosaic num
            BAIL_IF(add_new_field(context, NEM_UINT32_MOSAIC_COUNT, STI_UINT32, sizeof(uint32_t), (uint8_t *) &numMosaic));
            for (uint32_t i = 0; i < numMosaic; i++) {
                // mosaic structure length pointer
                if (move_pos(context, sizeof(uint32_t)) == NULL) { // Move position and security check
                    return E_NOT_ENOUGH_DATA;
                }
                // mosaicId structure length pointer
                if (move_pos(context, sizeof(uint32_t)) == NULL) { // Move position and security check
                    return E_NOT_ENOUGH_DATA;
                }

                // namespaceID length pointer
                uint32_t nsIdLen;
                BAIL_IF(_read_uint32(context, &nsIdLen));
                // namespaceID pointer
                ptr = read_data(context, nsIdLen); // Read data and security check
                if (ptr == NULL) {
                    return E_NOT_ENOUGH_DATA;
                }
                sprintf_ascii(str, 32, ptr, nsIdLen);
                uint8_t is_nem = 0; //namespace is nem
                if (strcmp(str, "nem") == 0) {
                    is_nem = 1;
                }
                // mosaic name length pointer
                uint32_t mosaicNameLen;
                BAIL_IF(_read_uint32(context, &mosaicNameLen))
                // mosaic name and quantity
                if (mosaicNameLen > UINT32_MAX - sizeof(uint64_t)) {
                    return E_INVALID_DATA;
                }                
                ptr = read_data(context, mosaicNameLen + sizeof(uint64_t)); // Read data and security check
                if (ptr == NULL) {
                    return E_NOT_ENOUGH_DATA;
                }
                sprintf_ascii(str, 32, ptr, mosaicNameLen);
                if (is_nem == 1 && strcmp(str, "xem") == 0) {
                    // xem quantity
                    BAIL_IF(add_new_field(context, NEM_MOSAIC_AMOUNT, STI_NEM, sizeof(uint64_t), (uint8_t *)(ptr + mosaicNameLen)));
                } else {
                    // mosaic name and quantity
                    BAIL_IF(add_new_field(context, NEM_MOSAIC_UNITS, STI_MOSAIC_CURRENCY, mosaicNameLen + sizeof(uint64_t), ptr));
                }
            }
        }
    }
    return 0;
}

static int parse_importance_transfer_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    importance_txn_header_t *txn = (importance_txn_header_t*) read_data(context, sizeof(importance_txn_header_t)); // Read data and security check
    if (txn == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    //  Show importance transfer mode
    BAIL_IF(add_new_field(context, NEM_UINT32_IT_MODE, STI_UINT32, sizeof(uint8_t), (uint8_t*) &txn->iMode));
    // Show public key of remote account
    BAIL_IF(add_new_field(context, NEM_PUBLICKEY_IT_REMOTE, STI_HASH256, NEM_PUBLIC_KEY_LENGTH, (uint8_t*) &txn->iPublicKey.publicKey));
    // Show fee
    BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee));
    return 0;
}

static int parse_aggregate_modification_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    uint32_t cmNum;    
    BAIL_IF(_read_uint32(context, &cmNum));
    // Show number of cosignatory modification
    add_new_field(context, NEM_UINT32_AM_COSIGNATORY_NUM, STI_UINT32, sizeof(uint32_t), (uint8_t *) &cmNum);
    for (uint32_t i = 0; i < cmNum; i++) {
        aggregate_modication_header_t *txn = (aggregate_modication_header_t*) read_data(context, sizeof(aggregate_modication_header_t)); // Read data and security check
        if (txn == NULL) {
            return E_NOT_ENOUGH_DATA;
        }
        //  Show modification type
        BAIL_IF(add_new_field(context, NEM_UINT32_AM_MODICATION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &txn->amType));
        // Show public key of cosignatory
        BAIL_IF(add_new_field(context, NEM_PUBLICKEY_AM_COSIGNATORY, STI_HASH256, NEM_PUBLIC_KEY_LENGTH, (uint8_t*) &txn->amPublicKey.publicKey));
    }
    if (common_header->version == 2) {
        uint32_t cmLen;
        BAIL_IF(_read_uint32(context, &cmLen));
        if (cmLen > 0) {
            // Show relative change in minimum cosignatories modification structure
            uint32_t minCm;
            BAIL_IF(_read_uint32(context, &minCm));
            BAIL_IF(add_new_field(context, NEM_UINT32_AM_RELATIVE_CHANGE, STI_UINT32, sizeof(uint32_t), (uint8_t *) &minCm)); // Read data and security check
        } else {
            // Show no minimum cosignatories modification
            add_new_field(context, NEM_UINT32_AM_RELATIVE_CHANGE, STI_UINT32, sizeof(uint32_t), (uint8_t *) &cmLen);
        }
    }
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee);
    return 0;
}

static int parse_multisig_signature_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    multsig_signature_header_t *txn = (multsig_signature_header_t*) read_data(context, sizeof(multsig_signature_header_t)); // Read data and security check
    if (txn == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    // Show sha3 hash
    if (txn->hashLen > NEM_TRANSACTION_HASH_LENGTH) {
        return E_INVALID_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_HASH256, STI_HASH256, txn->hashLen, (uint8_t*) &txn->hash));
    // Show multisig address
    BAIL_IF(add_new_field(context, NEM_STR_MULTISIG_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &txn->msAddress.address));
    // Show fee
    BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee));
    return 0;
}

static int parse_provision_namespace_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    uint32_t len;

    rental_header_t *txn = (rental_header_t*) read_data(context, sizeof(rental_header_t)); // Read data and security check
    if (txn == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    BAIL_IF(_read_uint32(context, &len)); // Read uint32 and security check
    
    // New part string
    BAIL_IF(_read_uint32(context, &len));
    const uint8_t *ptr = read_data(context, len);
    if (ptr == NULL) {
        return E_INVALID_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, ptr));

    BAIL_IF(_read_uint32(context, &len));  // Read uint32 and security check
    if (len == UINT32_MAX) {
        // Show create new root namespace
        BAIL_IF(add_new_field(context, NEM_STR_ROOT_NAMESPACE, STI_STR, 0, NULL));
    } else {
        // Show parent namespace string
        ptr = read_data(context, len);
        if (ptr == NULL) {
            return E_INVALID_DATA;
        }
        BAIL_IF(add_new_field(context, NEM_STR_PARENT_NAMESPACE, STI_STR, len, ptr)); // Read data and security check
    }
    // Show sink address
    if (txn->rAddress.length > NEM_ADDRESS_LENGTH) {
        return E_INVALID_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_STR_SINK_ADDRESS, STI_ADDRESS, txn->rAddress.length, (uint8_t*) &txn->rAddress.address));
    // Show rental fee
    BAIL_IF(add_new_field(context, NEM_UINT64_RENTAL_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &txn->rentalFee));
    // Show fee./
    BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee));
    return 0;
}

static int parse_mosaic_definition_creation_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    const uint8_t* ptr;
    uint32_t propertyNum;
    uint32_t len;

    mosaic_definition_creation_t *txn = (mosaic_definition_creation_t*) read_data(context, sizeof(mosaic_definition_creation_t)); // Read data and security check
    if (txn == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    // Show namespace id string
    const uint8_t *namespaceId = read_data(context, txn->nsIdLen);
    if (namespaceId == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_STR_PARENT_NAMESPACE, STI_STR, txn->nsIdLen, namespaceId)); // Read data and security check
    
    // Show mosaic name string
    BAIL_IF(_read_uint32(context, &len));
    ptr = read_data(context, len);
    if (ptr == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_STR_MOSAIC, STI_STR, len, ptr));

    // Show description string
    BAIL_IF(_read_uint32(context, &len));
    ptr = read_data(context, len);
    if (ptr == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    add_new_field(context, NEM_STR_DESCRIPTION, STI_STR, len, ptr); // Read data and security check

    BAIL_IF(_read_uint32(context, &propertyNum)); // Read uint32 and security check
    for (uint32_t i = 0; i < propertyNum; i++) {
        // Length of the property structure
        move_pos(context, sizeof(uint32_t)); // Move position and security check
        // Length of the property name
        ptr = read_data(context, sizeof(uint32_t)); // Read data and security check
        if (ptr == NULL) {
            return E_NOT_ENOUGH_DATA;
        }
        len = read_uint32(ptr);
        // Show property name string
        if (move_pos(context, len) == NULL) { // Move position and security check
            return E_NOT_ENOUGH_DATA;
        }
        BAIL_IF(_read_uint32(context, &len)); // Read uint32 and security check
        // Show property value string
        if (move_pos(context, len) == NULL) { // Move position and security check
            return E_NOT_ENOUGH_DATA;
        }
        // data = len name, name, len value, value (ignore length)
        BAIL_IF(add_new_field(context, NEM_STR_PROPERTY, STI_PROPERTY, sizeof(uint32_t), ptr));
    }
    // Levy structure length
    BAIL_IF(_read_uint32(context, &len));  // Read uint32 and security check
    if(len > 0) {
        if (has_data(context, len)) { // Security check
            uint32_t nsid_len;

            levy_structure_t *levy = (levy_structure_t*) read_data(context, sizeof(levy_structure_t)); // Read data and security check
            if (levy == NULL) {
                return E_NOT_ENOUGH_DATA;
            }

            ptr = read_data(context, sizeof(uint32_t));
            if (ptr == NULL) {
                return E_NOT_ENOUGH_DATA;
            }
            ptr += sizeof(uint32_t);

            //Length of namespace id string
            BAIL_IF(_read_uint32(context, &nsid_len));
            //namespaceid
            if (move_pos(context, nsid_len) == NULL) { // Move position and security check
                return E_NOT_ENOUGH_DATA;
            }
            uint32_t mn_len;
            BAIL_IF(_read_uint32(context, &mn_len)); // Read uint32 and security check
            //mosaic name
            if (move_pos(context, mn_len) == NULL) { // Move position and security check
                return E_NOT_ENOUGH_DATA;
            };
            // Show levy mosaic: namespace:mosaic name, data=len nemspaceid, nemspaceid, len mosaic name, mosiac name
            BAIL_IF(add_new_field(context, NEM_STR_LEVY_MOSAIC, STI_STR, nsid_len + mn_len + 2 * sizeof(uint32_t), (uint8_t *) ptr));
            // Show levy address
            BAIL_IF(add_new_field(context, NEM_STR_LEVY_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &levy->lsAddress.address));
            // Show levy fee type
            BAIL_IF(add_new_field(context, NEM_UINT32_LEVY_FEE_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &levy->feeType));
            // Show levy fee
            ptr = read_data(context, sizeof(uint64_t));
            if (ptr == NULL) {
                return E_NOT_ENOUGH_DATA;
            }
            BAIL_IF(add_new_field(context, NEM_UINT64_LEVY_FEE, STI_NEM, sizeof(uint64_t), ptr)); // Read data and security check
        }  else {
            return E_NOT_ENOUGH_DATA;
        }
    }
    mosaic_definition_sink_t *sink = (mosaic_definition_sink_t*) read_data(context, sizeof(mosaic_definition_sink_t)); // Read data and security check
    if (sink == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    // Show sink address
    BAIL_IF(add_new_field(context, NEM_STR_SINK_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &sink->mdAddress.address));
    // Show rentail fee
    BAIL_IF(add_new_field(context, NEM_UINT64_RENTAL_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &sink->fee));
    // Show tx fee
    BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee));
    return 0;
}

static int parse_mosaic_supply_change_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    uint32_t len;
    const uint8_t *ptr;

    //Length of mosaic id structure
    BAIL_IF(_read_uint32(context, &len)); // Read uint32 and security check
    //Length of namespace id string: 4
    BAIL_IF(_read_uint32(context, &len));  // Read uint32 and security check
    // Show namespace id string
    ptr = read_data(context, len);
    if (ptr == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_STR_NAMESPACE, STI_STR, len, ptr)); // Read data and security check
    //Length of mosaic name string
    BAIL_IF(_read_uint32(context, &len)); // Read uint32 and security check
    
    // Show mosaic name string
    BAIL_IF(_read_uint32(context, &len));
    ptr = read_data(context, len);
    if (ptr == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_STR_MOSAIC, STI_STR, len, ptr));

    len = sizeof(uint32_t) + sizeof(uint64_t);
    // supply type and delta change
    ptr = read_data(context, len);
    if (ptr == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    BAIL_IF(add_new_field(context, NEM_MOSAIC_SUPPLY_DELTA, STI_MOSAIC_CURRENCY, len, ptr)); // Read data and security check
    // Show fee
    BAIL_IF(add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_header->fee));
    return 0;
}

static int parse_multisig_transaction(parse_context_t *context, common_txn_header_t *common_header) {
    // Length of inner transaction object.
    // This can be a transfer, an importance transfer or an aggregate modification transaction
    uint32_t innerTxnLength;
    
    BAIL_IF(_read_uint32(context, &innerTxnLength)); // Read uint32 and security check
    if (has_data(context, innerTxnLength)) { // Security check
        add_new_field(context, NEM_UINT64_MULTISIG_FEE, STI_NEM, sizeof(uint32_t), (uint8_t*) &common_header->fee);
        uint32_t innerOffset = 0;
        while (innerOffset < innerTxnLength) {
            uint32_t previousOffset = context->offset;
            // get header first
            common_txn_header_t *inner_header = (common_txn_header_t*) read_data(context, sizeof(common_txn_header_t)); // Read data and security check
            if (inner_header == NULL) {
                return E_NOT_ENOUGH_DATA;
            }
            // Show inner transaction type
            add_new_field(context, NEM_UINT32_INNER_TRANSACTION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &inner_header->transactionType);
            switch (inner_header->transactionType) {
                case NEM_TXN_TRANSFER:
                    parse_transfer_transaction(context, inner_header);
                    break;
                case NEM_TXN_IMPORTANCE_TRANSFER:
                    parse_importance_transfer_transaction(context, inner_header);
                    break;
                case NEM_TXN_MULTISIG_AGGREGATE_MODIFICATION:
                    parse_aggregate_modification_transaction(context, inner_header);
                    break;
                case NEM_TXN_MULTISIG_SIGNATURE:
                    parse_multisig_signature_transaction(context, inner_header);
                    break;
                case NEM_TXN_MULTISIG:
                    parse_multisig_transaction(context, inner_header);
                    break;
                case NEM_TXN_PROVISION_NAMESPACE:
                    parse_provision_namespace_transaction(context, inner_header);
                    break;
                case NEM_TXN_MOSAIC_DEFINITION:
                    BAIL_IF(parse_mosaic_definition_creation_transaction(context, inner_header));
                    break;
                case NEM_TXN_MOSAIC_SUPPLY_CHANGE:
                    BAIL_IF(parse_mosaic_supply_change_transaction(context, inner_header));
                    break;
                default:
                    return E_INVALID_DATA;
            }
            innerOffset = innerOffset + context->offset - previousOffset;
        }
    } else {
        return E_NOT_ENOUGH_DATA;
    }
    return 0;
}

static int parse_txn_detail(parse_context_t *context, common_txn_header_t *common_header) {
    int err;
    context->result.numFields = 0;
    // Show Transaction type
    BAIL_IF(add_new_field(context, NEM_UINT32_TRANSACTION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &common_header->transactionType));
    switch (common_header->transactionType) {
        case NEM_TXN_TRANSFER:
            err = parse_transfer_transaction(context, common_header);
            break;
        case NEM_TXN_IMPORTANCE_TRANSFER:
            err = parse_importance_transfer_transaction(context, common_header);
            break;
        case NEM_TXN_MULTISIG_AGGREGATE_MODIFICATION:
            err = parse_aggregate_modification_transaction(context, common_header);
            break;
        case NEM_TXN_MULTISIG_SIGNATURE:
            err = parse_multisig_signature_transaction(context, common_header);
            break;
        case NEM_TXN_MULTISIG:
            err = parse_multisig_transaction(context, common_header);
            break;
        case NEM_TXN_PROVISION_NAMESPACE:
            err = parse_provision_namespace_transaction(context, common_header);
            break;
        case NEM_TXN_MOSAIC_DEFINITION:
            err = parse_mosaic_definition_creation_transaction(context, common_header);
            break;
        case NEM_TXN_MOSAIC_SUPPLY_CHANGE:
            err = parse_mosaic_supply_change_transaction(context, common_header);
            break;
        default:
            err = E_INVALID_DATA;
            break;
    }
    return err;
}

static common_txn_header_t *parse_common_header(parse_context_t *context) {
    // get gen_hash and transaction_type
    common_txn_header_t *common_header = (common_txn_header_t *) read_data(context, sizeof(common_txn_header_t)); // Read data and security check
    if (common_header == NULL) {
        return NULL;
    }
    context->version = common_header->version;
    return common_header;
}

int parse_txn_context(parse_context_t *context) {
    common_txn_header_t* txn = parse_common_header(context);
    if (txn == NULL) {
        return E_NOT_ENOUGH_DATA;
    }
    return parse_txn_detail(context, txn);
}
