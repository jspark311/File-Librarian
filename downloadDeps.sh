#!/bin/bash

mkdir lib

rm -rf lib/CppPotpourri
git clone --depth=1 https://github.com/jspark311/CppPotpourri lib/CppPotpourri

rm -rf lib/ManuvrPlatform lib/Platform
git clone --depth=1 https://github.com/jspark311/ManuvrPlatform lib/ManuvrPlatform
ln -s lib/Platform lib/ManuvrPlatform/Linux

# mbedTLS...
rm -rf lib/mbedtls
git clone --depth=1 https://github.com/ARMmbed/mbedtls.git lib/mbedtls
