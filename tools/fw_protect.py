#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
import cryptography
import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
import pycryptodome


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Append firmware to message, separated by a null byte
    message_and_firmware = message.encode() + b'\00' + firmware

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Hash the firmware using SHA-256
    hash = SHA256.new()
    hash.update(firmware_and_message)
    # digest = hashes.Hash(hashes.SHA256())
    # digest.update(firmware_and_message)
    firmware_hash = hash.hexdigest()

    # Load secrets for encryption and signing
    with open("secret_build_output.txt", 'r') as secrets_fp:
        secrets = secrets_fp.read()

    # Splits the keys with the new line ther are index 0 - AES key, 1- RSA Private Key, 2- RSA Public Key
    secrets = secrets.split('\n\n')

    # Assign the 0,1 index in secrets to aes_key
    aes_key1 = secrets[0]
    aes_key2 = secrets[1]
    
    # Make an IV
    aes_cbc_iv = os.urandom(10) 

    # Encrypt metadata+firmware with AES-GCM
    all_data = metadata + message_and_firmware
    cipher = AES.new(aes_key1, AES.MODE_CBC,iv=aes_cbc_iv)
    ciphertext, tag = cipher.encrypt_and_digest(all_data)

    # Encrypt AES-GCM IV with AES
    ciphertext_iv = ciphertext + aes_cbc_iv
    cipher = AES.new(aes_key2, AES.MODE_GCM)
    ciphertext_final, tag = cipher.encrypt_and_digest(ciphertext_iv)

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(ciphertext_final)

#python3 fw_protect.py --infile firmware.ld --outfile protected_firmware.bin --version 1.0.0 --message "Update Message"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)




# metadata, firmware, hash , IV 
# verison size message null firmware , hash 0x20 , CBC_IV 0x10
################## AES_CBC ENCRYPTION ###########
################################### AES_GCM ##################