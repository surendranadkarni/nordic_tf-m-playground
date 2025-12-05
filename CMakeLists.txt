#
# Copyright (c) 2021 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: LicenseRef-Nordic-5-Clause
#

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(aes_cbc_nordic)

target_sources(app PRIVATE
        src/main.c src/ecdsa_test.c src/hmac_test.c 
        )
