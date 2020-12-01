#!/usr/bin/env python3
# *******************************************************************************
# *   NEM Wallet
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

import argparse
from base import send_hex

parser = argparse.ArgumentParser()
parser.add_argument('--path', help="BIP32 path to retrieve.")
parser.add_argument('--ed25519', help="Derive on ed25519 curve", action='store_true')
parser.add_argument("--apdu", help="Display APDU log", action='store_true')
args = parser.parse_args()

FIRST_TEST_TX =  "E0048080FF058000002C8000002B8000009880000000800000000410000001000098B466AE0A200000009F96DF7E7A639B4034B8BEE5B88AB1D640DB66EB5A47AFE018E320CB130C183DF049020000000000C474AE0ACB0100000140000001000098B466AE0A20000000180158D9FEED1711FBFC7718ED144275311DCFD10A4480035D1856CDAC7242ABF049020000000000C474AE0A5701000020000000180158D9FEED1711FBFC7718ED144275311DCFD10A4480035D1856CDAC7242AB2900000008000000746573745F6E656D190000006D6F736169635F6372656174655F66726F6D5F6C65646765724100000054686973206D6F7361696320697320637265617465"
MORE_TEST_TX = "E0048180FF642062792061206C65646765722077616C6C65742066726F6D2061206D756C7469736967206163636F756E7404000000150000000C00000064697669736962696C6974790100000033190000000D000000696E697469616C537570706C790400000031303030190000000D000000737570706C794D757461626C650400000074727565180000000C0000007472616E7366657261626C6504000000747275654A000000010000002800000054423749423644534A4B57425651454B3750443754574F3636454357354C59365349534D32434A4A0E000000030000006E656D0300000078656D05000000000000002800000054424D4F534149434F4434463534"
LAST_TEST_TX = "E00401802245453543444D523233434342474F414D3258534A4252354F4C438096980000000000"

print("-= NEM Ledger =-")
print("Sign a multisig create mosaic transaction")
print("Please confirm on your Ledger Nano S")

result1 = send_hex(FIRST_TEST_TX)
result2 = send_hex(MORE_TEST_TX)
result3 = send_hex(LAST_TEST_TX)