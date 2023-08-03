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
from Crypto.Util.Padding import pad
from pwn import p16

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()


    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))
    version_pack = p16(version, endian = "little")

    # Hash the firmware using SHA-256
    hash = SHA256.new()
    hash.update(firmware)
    firmware_hash = bytes(hash.digest())

    # Load secrets for encryption and signing
    with open("secret_build_output.txt", 'rb') as secrets_fp:
        aes_key1 = secrets_fp.readline() #pulls cbc key from file
        aes_key2 = secrets_fp.readline() #pulls gcm key from file
        gcm_aad = secrets_fp.readline() #pulls aad from file

        aes_key1 = aes_key1[0:-1] #drops newline character
        aes_key2 = aes_key2[0:-1] #drops newline character
    # Make an IV
    aes_cbc_iv = os.urandom(16) 
    #aes_gcm_nonce = os.urandom(16) #for aes gcm 
    
    # Encrypt firmware + hash with AES-CBC
    firmware_all = firmware + firmware_hash
    print(firmware_all)
    print('/n')
    cipher = AES.new(aes_key1, AES.MODE_CBC,iv=aes_cbc_iv)
    length_pack = p16(len(firmware_all ), endian = "little")
    if len(firmware_all)%16 !=0:
        firmware_all = pad(firmware_all,16)
    ciphertext = cipher.encrypt(firmware_all)

    # Encrypt version + message + previous message + CBC_IV with AES-GCM
    # cipher = AES.new(aes_key2, AES.MODE_GCM, nonce = aes_gcm_nonce)
    # cipher.update(gcm_aad)

    msg_size = p16(len(message.encode()), endian = "little")
    ciphertext_final = version_pack + msg_size + message.encode() + ciphertext + aes_cbc_iv 
    
    # ciphertext_final, tag = cipher.encrypt_and_digest(pad(ciphertext_all,16))
    ciphertext_final = length_pack + ciphertext_final# + aes_gcm_nonce + tag
    # Write firmware blob to outfile
    print(ciphertext_final)
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




                  # size verison msg_size message        firmware , hash 0x20 , CBC_IV 0x10, GCM_Nonce, tag
 #Encrypt1                                      #AES_CBC ENCRYPTION#                                #Decrypt2
 #Encrypt2               ############### AES_GCM #################################                  #Decrypt1
                         #########3###### LENGTH  ################################