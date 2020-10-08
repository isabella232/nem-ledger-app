#!/bin/bash -i
source ~/NEM/ledger3/bin/activate
# export BOLOS_ENV=~/bolos-devenv
# export BOLOS_SDK=~/NEM/nanos-secure-sdk
export BOLOS_SDK=~/NEM/nanos-secure-sdk
export PATH=~/NEM/gcc-arm-none-eabi-5_3-2016q1/bin/:$PATH
export PATH=~/NEM/clang+llvm-7.0.0-x86_64-linux-gnu-ubuntu-16.04/bin/:$PATH
export SCP_PRIVKEY=507b4b608b947e0cc534161750a905db4d1cae6483cd5f7c7c5b2c4f9ca6bcb3       NewLedger
# export SCP_PRIVKEY=76b3ef030b94609a2a9e1c0ae6ef23066515715f79c6e0a3a8d82bb970f86a30
make $1 load
