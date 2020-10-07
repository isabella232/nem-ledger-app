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
#include "nem/nem_helpers.h"

#define TRANSFER_TXN_HEADER_LENGTH           52
typedef struct {
    uint8_t recipientAddress[NEM_ADDRESS_LENGTH];
    uint64_t amount;
    uint32_t messageLength;
} transfer_txn_header_t;

#define IMPORTANCE_TRANSFER_TXN_HEADER_LENGTH 40
typedef struct {
    uint32_t importanceMode;
    uint32_t publicKeyLength;
    uint8_t publicKey[32];
} importance_tranfer_header_t;

#define AGGREGATE_MODIFICATION_HEADER_LENGTH    44
typedef struct {
    uint32_t cosignatoryModificationLength;
    uint32_t modicationType;
    uint32_t cosignatoryPublicKeyLength;
    uint8_t cosignatoryPublicKey[32];
} aggregate_modication_header_t;

#define MULTISIG_SIGNATURE_HEADER_LENGTH        84

typedef struct {
    uint32_t hashObjectLength;
    uint32_t hashLength;
    uint8_t hash[32];
    uint32_t addressLength;
    uint8_t address[40];
} multsig_signature_header_t;

#define COSIGNATORIES_MODIFICATION_HEADER_LENGTH  8
typedef struct {
    uint32_t minCosignatoriesModification;
    uint32_t relativeChange;
} cosignatories_modification_header_t;

#define PROVISION_NAMESPACE_HEADER_LENGTH    56
typedef struct {
    uint32_t sinkAddressLength;
    uint8_t sinkAddress[NEM_ADDRESS_LENGTH];
    uint64_t rentailFee;
    uint32_t newPartLength;
} provision_namespace_header_t;



#define MOSAIC_DEFINITION_CREATION_HEADER_LENGTH    48
typedef struct {
    uint32_t definitionStructureLength;
    uint32_t publicKeyLenght;
    uint8_t publicKey[32];
    uint32_t idStructureLength;
    uint32_t namespaceIdLength;
} mosaic_definition_creation_t;


#define INNER_TX_HEADER_LENGTH      48
typedef struct {
    uint32_t size;
    uint32_t reserve1;
    uint8_t signerPublicKey[NEM_PUBLIC_KEY_LENGTH];
    uint32_t reserve2;
    uint8_t version;
    uint8_t network;
    uint16_t innerTxType;
} inner_tx_header_t;



#define MUTLISIG_ACCOUNT_HEADER_LENGTH 8
typedef struct {
    int8_t minRemovalDelta;
    int8_t minApprovalDelta;
    uint8_t addressAdditionsCount;
    uint8_t addressDeletionsCount;
    uint32_t reserve;
} multisig_account_t;

#define COMMON_TX_HEADER_LENGTH             64
typedef struct {
    uint32_t transactionType;
    uint32_t version;
    uint32_t timestamp;
    uint32_t publicKeyLength;
    uint8_t publicKey[NEM_PUBLIC_KEY_LENGTH];
    uint64_t fee;
    uint32_t deadline;
} common_transaction_part_t;

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
        return context->data + offset;
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void advance_position(parse_context_t *context, uint32_t numBytes) {
    if (has_data(context, numBytes)) {
        context->offset += numBytes;
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}

void parse_transfer_txn_content(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    transfer_txn_header_t *txn = (transfer_txn_header_t*) read_data(context, TRANSFER_TXN_HEADER_LENGTH);
    // Show Recipient address
    add_new_field(context, NEM_STR_RECIPIENT_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &txn->recipientAddress);
    // Show xem amount
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &txn->amount);
    PRINTF("\nMessage length: %x\n%x\n", txn->messageLength, txn->amount);
    if (txn->messageLength > 0) {
        payload_header_t *pl = (payload_header_t*) read_data(context, PAYLOAD_HEADER_LENGTH);
        PRINTF("payload length: %x, msg type %x\n", pl->payloadLength, pl->payloadType);
        // Show Message
        add_new_field(context, NEM_STR_TXN_MESSAGE, STI_MESSAGE, pl->payloadLength, read_data(context, pl->payloadLength));
    }
    if (context->version == 2) {
        data_uint32_t *mosaicNum = (data_uint32_t*) read_data(context, DATA_UINT32_HEADER_LENGTH);
        // // Show sent other mosaic num
        add_new_field(context, NEM_UINT8_MOSAIC_COUNT, STI_UINT8, DATA_UINT32_HEADER_LENGTH, (uint8_t*) &mosaicNum->data32);
        for (uint32_t i = 0; i < 1; i++) {
            mosaic_t *mosaic = (mosaic_t*) read_data(context, MOSAIC_HEADER_LENGTH);
            // todo add mosaic order
            // Field:       Mosaic
            // Format:   (1/{mosaicNum})
            // Show namespace id string
            add_new_field(context, NEM_STR_NAMESPACE, STI_STR, mosaic->namespaceIdLength, read_data(context, mosaic->namespaceIdLength));
            PRINTF("Namespace done\n");
            data_uint32_t *mosaicName = (data_uint32_t*) read_data(context, DATA_UINT32_HEADER_LENGTH);
            // PRINTF("mosaic name %x\n", mosaicName->data32);
            // Show mosaic name string
            add_new_field(context, NEM_STR_NAMESPACE, STI_STR, mosaic->namespaceIdLength, read_data(context, mosaic->namespaceIdLength));
            // // PRINTF("Mosaic quan start\n");
            // Show mosaic quantity
            add_new_field(context, NEM_MOSAIC_AMOUNT, STI_MOSAIC_CURRENCY, sizeof(uint64_t), read_data(context, sizeof(uint64_t)));
            // PRINTF("Mosaic quan done\n");
        }
    }
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_tx_part->fee);

}

void parse_importance_tranfer_txn_content(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    importance_tranfer_header_t *txn = (importance_tranfer_header_t*) read_data(context, IMPORTANCE_TRANSFER_TXN_HEADER_LENGTH);
    //  Show importance transfer mode
    add_new_field(context, NEM_UINT8_AA_TYPE, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->importanceMode);
    // Show public key of remote account
    add_new_field(context, NEM_HASH256_AGG_HASH, STI_HASH256, NEM_PUBLIC_KEY_LENGTH, (uint8_t*) &txn->publicKey);
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_tx_part->fee);
}

void parse_aggregate_modification_txn_content(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    uint32_t cosignatoriesModificationNum = read_uint32(read_data(context, sizeof(uint32_t)));
    // todo
    // Add number of cosignatory modification
    for (uint32_t i = 0; i < cosignatoriesModificationNum; i++) {
        aggregate_modication_header_t *txn = (aggregate_modication_header_t*) read_data(context, AGGREGATE_MODIFICATION_HEADER_LENGTH);

    }
    // Show min removal delta
    add_new_field(context, NEM_INT8_MAM_REMOVAL_DELTA, STI_INT8, sizeof(int8_t), (uint8_t*) &txn->minRemovalDelta);
    // Show min approval delta
    add_new_field(context, NEM_INT8_MAM_APPROVAL_DELTA, STI_INT8, sizeof(int8_t), (uint8_t*) &txn->minApprovalDelta);
    // Show address additions count
    add_new_field(context, NEM_UINT8_MAM_ADD_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->addressAdditionsCount);
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressAdditionsCount; i++) {
        add_new_field(context, NEM_STR_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, read_data(context, NEM_ADDRESS_LENGTH));
    }
    // Show address deletions count
    add_new_field(context, NEM_UINT8_MAM_DEL_COUNT, STI_UINT8, sizeof(uint8_t), (uint8_t*) &txn->addressDeletionsCount);
    // Show list of addition address
    for (uint8_t i = 0; i < txn->addressDeletionsCount; i++) {
        add_new_field(context, NEM_STR_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, read_data(context, NEM_ADDRESS_LENGTH));
    }
}

void parse_multisig_signature_txn_context(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    multsig_signature_header_t *txn = (multsig_signature_header_t*) read_data(context, MULTISIG_SIGNATURE_HEADER_LENGTH);
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_tx_part->fee)
}

void parse_inner_txn_content(parseContext_t *context, uint32_t len) {
    uint32_t totalSize = 0;
    do {
        // get header first
        inner_tx_header_t *txn = (inner_tx_header_t*) read_data(context, INNER_TX_HEADER_LENGTH);
        totalSize += txn->size + 2;
        // Show Transaction type
        add_new_field(context, NEM_UINT32_INNER_TRANSACTION_TYPE, STI_UINT32, sizeof(uint32_t), (uint8_t*) &txn->innerTxType);
        switch (txn->innerTxType) {
            case NEM_TXN_TRANSFER:
                parse_transfer_txn_content(context, true);
                break;
            default:
                break;
        }
        if (totalSize < len-5) {
            advance_position(context, 2);
        }
    } while (totalSize < len-5);
}

void parse_multisig_txn_context(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    uint32_t innerTxnLength = read_uint32(read_data(context, sizeof(uint32_t)));
    if (has_data(context, innerTxnLength)) {
        parse_inner_txn_content(context, innerTxnLength);
    } else {
        THROW(EXCEPTION_OVERFLOW);
    }
}


void parse_provision_namespace_txn_content(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    for (uint8_t i = 0; i<20; i++) {
        PRINTF("%02x", *(context->data +i));
    }
    provision_namespace_header_t *txn = (provision_namespace_header_t*) read_data(context, PROVISION_NAMESPACE_HEADER_LENGTH);
    // Show sink address
    add_new_field(context, NEM_STR_ADDRESS, STI_ADDRESS, NEM_ADDRESS_LENGTH, (uint8_t*) &txn->sinkAddress);
    // Add rental fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &txn->rentailFee);
    // // New part string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, txn->newPartLength, read_data(context, txn->newPartLength));
    uint32_t *parentStringLength = (uint32_t*) read_data(context, sizeof(uint32_t));
    // if (parentStringLength != 0xffffffff ) {
    //     // Parent string
    //     add_new_field(context, NEM_STR_NAMESPACE, STI_STR, parentStringLength, read_data(context, parentStringLength));
    // }
    // Show fee
    add_new_field(context, NEM_UINT64_TXN_FEE, STI_NEM, sizeof(uint64_t), (uint8_t*) &common_tx_part->fee);

}

void parse_mosaic_definition_creation_txn_content(parse_context_t *context, common_transaction_part_t *common_tx_part) {
    mosaic_definition_creation_t *txn = (mosaic_definition_creation_t*) read_data(context, MOSAIC_DEFINITION_CREATION_HEADER_LENGTH);
    // Show namespace id string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, txn->namespaceIdLength, read_data(context, txn->namespaceIdLength));
    uint32_t mosaicNameLength = read_uint32(read_data(context, sizeof(uint32_t)));
    // Show mosaic name string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, mosaicNameLength, read_data(context, mosaicNameLength));
    uint32_t descriptionLength = read_uint32(read_data(context, sizeof(uint32_t)));
    // Show description string
    add_new_field(context, NEM_STR_NAMESPACE, STI_STR, descriptionLength, read_data(context, descriptionLength));
    uint32_t propertyNum = read_uint32(read_data(context, sizeof(uint32_t)));
    for (uint32_t i = 0; i < propertyNum; i++) {
        // Property structure length
        advance_position(context, sizeof(uint32_t));
        uint32_t propertyNameLength = read_uint32(read_data(context, sizeof(uint32_t)));
        // Show property name string
        add_new_field(context, NEM_STR_NAMESPACE, STI_STR, propertyNameLength, read_data(context, propertyNameLength));
        uint32_t propertyValueLength = read_uint32(read_data(context, sizeof(uint32_t)));
        // Show property value string
        add_new_field(context, NEM_STR_NAMESPACE, STI_STR, propertyValueLength, read_data(context, propertyValueLength));
    }
    // Levy structure length
    uint32_t levyStructureLength = read_uint32(read_data(context, sizeof(uint32_t)));
    if(levyStructureLength != )
}


void parse_txn_detail(parse_context_t *context, common_transaction_part_t *txn) {
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
        case NEN_TXN_PROVISION_NAMESPACE:
            PRINTF("provision namespace\n");
            parse_provision_namespace_txn_content(context, txn);
            break;
        default:
            // Mask real cause behind generic error (INCORRECT_DATA)
            THROW(0x6A80);
            break;
    }
}

void set_sign_data_length(parse_context_t *context) {
    if ((context->transactionType == NEM_TXN_AGGREGATE_COMPLETE) || (context->transactionType == NEM_TXN_AGGREGATE_BONDED)) {
        const unsigned char TESTNET_GENERATION_HASH[] = {0x1D, 0xFB, 0x2F, 0xAA, 0x9E, 0x7F, 0x05, 0x41,
                                                        0x68, 0xB0, 0xC5, 0xFC, 0xB8, 0x4F, 0x4D, 0xEB,
                                                        0x62, 0xCC, 0x2B, 0x4D, 0x31, 0x7D, 0x86, 0x1F,
                                                        0x31, 0x68, 0xD1, 0x61, 0xF5, 0x4E, 0xA7, 0x8B};

        if (os_memcmp(TESTNET_GENERATION_HASH, context->data, NEM_TRANSACTION_HASH_LENGTH) == 0) {
            // Sign data from generation hash to transaction hash
            transactionContext.rawTxLength = 84;
        } else {
            // Sign transaction hash only
            transactionContext.rawTxLength = NEM_TRANSACTION_HASH_LENGTH;
        }
    } else {
        // Sign all data in the transaction
        transactionContext.rawTxLength = context->length;
    }
}

common_transaction_part_t *parse_common_tx_part(parse_context_t *context) {
    PRINTF("Parse tx common part\n");
    uint32_t length = sizeof(common_transaction_part_t);
    // get gen_hash and transaction_type
    common_transaction_part_t *txn = (common_transaction_part_t *) read_data(context, length);
    // Get the version the transaction
    context->version = txn->version;
    PRINTF("Version %x\n", context->version);
    return txn;
}

void parse_txn_internal(parse_context_t *context) {
    common_transaction_part_t* txn = parse_common_tx_part(context);
    parse_txn_detail(context, txn);
    set_sign_data_length(context);
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
