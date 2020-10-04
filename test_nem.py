#!/usr/bin/env python
# *******************************************************************************
# *   Ledger Blue
# *   (c) 2020 Ledger
# *   (c) 2020 FDS
# *
# *  Licensed under the Apache License, Version 2.0 (the "License");
# *  you may not use this file except in compliance with the License.
# *  You may obtain a copy of the License at
# *
# *      http://www.apache.org/licenses/LICENSE-2.0
# *
# *  Unless required by applicable law or agreed to in writing, software
# *  distributed under the License is distributed on an "AS IS" BASIS,
# *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# *  See the License for the specific language governing permissions and
# *  limitations under the License.
# ********************************************************************************
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException

TESTNET=152
MAINNET=104
MIJIN_MAINNET=96
MIJIN_TESTNET=144

bipp32_path = (
      "8000002C"
    + "8000002B"
    + "%s"
    + "80000000"
    + "80000000")
bipp32_path_len = "1505"

apdu = "E0020180"
dongle = getDongle(True)

def verify_address(network_type):
    network = hex(0x80000000 | network_type).lstrip("0x")
    bipp32 = bipp32_path % (network)
    print("bipp32_path: " + bipp32)
    result = dongle.exchange(bytes(bytearray.fromhex(apdu + bipp32_path_len + bipp32)))
    print("Result len: " + str(len(result)))
    print("Address respond       [" + str(result[0]) + "] " + result[1:41].decode())
    print("PublicKey respond       [" + str(result[41]) + "] " + result[42:74].hex().upper())

verify_address(TESTNET)