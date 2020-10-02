/*******************************************************************************
*    NEM Wallet
*    (c) 2020 Ledger
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
#ifndef LEDGER_APP_NEM_GLOBAL_H
#define LEDGER_APP_NEM_GLOBAL_H

#include <os.h>
#include <cx.h>
#include <stdbool.h>
#include "constants.h"
#include "limitations.h"

typedef enum {
    IDLE,
    WAITING_FOR_MORE,
    PENDING_REVIEW,
} signState_e;

typedef struct transactionContext_t {
    uint8_t pathLength;
    uint32_t bip32Path[MAX_BIP32_PATH];
    uint8_t rawTx[MAX_RAW_TX];
    uint32_t rawTxLength;
    cx_curve_t curve;
} transactionContext_t;

extern transactionContext_t transactionContext;
extern signState_e signState;

void reset_transaction_context();

#endif //LEDGER_APP_NEM_GLOBAL_H