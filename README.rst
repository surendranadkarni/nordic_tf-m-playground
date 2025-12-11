TF-M playground Sample Application
###############

.. contents::
   :local:
   :depth: 2

The AES CBC sample shows how to perform AES encryption and decryption operations using the CBC block cipher mode without padding and a 128-bit AES key.

Requirements
************

The sample is tested on nRF54L15 DK kit

Overview
********

The sample performs the following operations:

1. Initialization:

   a. The Platform Security Architecture (PSA) API is initialized.
   #. A random AES key is generated and imported into the PSA crypto keystore.

#. Encryption and decryption of a sample plaintext:

#. Sample to test ECDSA signature generation and verification:

#. Sample to test HMAC generation and verification:
#. Cleanup:



Building and running
********************

To build and run the sample application, follow these steps:
```
west build --build-dir ./build ./ --pristine --board nrf5340dk/nrf5340/cpuapp/ns --sysbuild -- -DEXTRA_CONF_FILE=./boards/nrf5340dk_nrf5340_cpuapp_ns.conf -DCONF_FILE="./prj.conf"
```

Testing
=======

After programming the sample to your development kit, complete the following steps to test it:

1. connect terminal emulator to the development kit UART port with the following settings:
   - Baud rate: 115200
   - Data bits: 8
   - Parity: None
   - Stop bits: 1
   - Flow control: None
#. Compile and program the the provisoning image application for nrf53 tehn flash the test application
```
west flash --erase --recover -d build_provisioning_image
```

flash application 

```
west flash -d build
```
#. Observe the logs from the application using a terminal emulator.
