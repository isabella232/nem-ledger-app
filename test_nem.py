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

apdu_get_account = "E0020180"
apdu_sign_tx = "E0040080"
dongle = getDongle(True)

def get_network_bipp32(network_type):
    return hex(0x80000000 | network_type).lstrip("0x")

def get_bipp32_path(network_type):
    return bipp32_path % (get_network_bipp32(network_type))

def send_package(data):
    result = dongle.exchange(data)
    print("Result len: " + str(len(result)))
    return result

def verify_address(network_type):
    bipp32_path_len = "1505"
    bipp32 = get_bipp32_path(network_type)
    result = send_package(bytes(bytearray.fromhex(apdu_get_account + bipp32_path_len + bipp32)))
    print("Address respond     [" + str(result[0]) + "] " + result[1:41].decode())
    print("PublicKey respond   [" + str(result[41]) + "] " + result[42:74].hex().upper())

def sign_transfer_tx(network_type):
    # bipp32 = get_bipp32_path(network_type)
    # TEST_TX =  "01010000010000989b5cd007200000003e6e6cbac488b8a44bdf5abf27b9e1cc2a6f20d09d550a66b9b36f525ca222eea086010000000000ab6ad007280000005441353435494341564e45554446554249484f3343454a425356495a37595948464658354c51505440420f00000000002000000001000000180000005369676e20746573746e6574207472616e73616374696f6e"
    # result = send_package(bytes(bytearray.fromhex(apdu_sign_tx + str(len(bipp32_path) + 1 + len(TEST_TX) + len(bipp32_path)/4, 'hex') + bipp32_path + TEST_TX)))
    # print(len(bipp32_path) + 1 + len(TEST_TX) + len(bipp32_path)/4)
    transfer_tx = "E0040080A9058000002C8000002B80000098800000008000000001010000010000989B5CD007200000003E6E6CBAC488B8A44BDF5ABF27B9E1CC2A6F20D09D550A66B9B36F525CA222EEA086010000000000AB6AD007280000005441353435494341564E45554446554249484F3343454A425356495A37595948464658354C51505440420F00000000002000000001000000180000005369676E20746573746E6574207472616E73616374696F6E"
    send_package(bytes(bytearray.fromhex(transfer_tx)))
# verify_address(TESTNET)

sign_transfer_tx(TESTNET)