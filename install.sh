#!/bin/bash
apt-get -y install git curl zip unzip tar pkg-config
git clone https://github.com/Microsoft/vcpkg.git
# shellcheck disable=SC1001
./vcpkg/bootstrap-vcpkg.sh
# shellcheck disable=SC1001
./vcpkg/vcpkg install crow
# shellcheck disable=SC1001
./vcpkg/vcpkg install hiredis
# shellcheck disable=SC1001
./vcpkg/vcpkg install redis-plus-plus
# shellcheck disable=SC1001
./vcpkg/vcpkg install nlohmann-json
# shellcheck disable=SC1001
./vcpkg/vcpkg install jwt-cpp
# shellcheck disable=SC1001
./vcpkg/vcpkg install mbedtls
# shellcheck disable=SC1001
./vcpkg/vcpkg install icu
exit 0