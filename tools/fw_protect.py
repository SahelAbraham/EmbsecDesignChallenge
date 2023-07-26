#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
import pycryptodome

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Hash the firmware using SHA-256
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(firmware_and_message)
    firmware_hash = digest.finalize()

    # Load secrets for encryption and signing
    with open(secrets_file, 'rb') as secrets_fp:
        secrets = secrets_fp.read()
    
    # Split secrets into AES key and RSA private key
    aes_key = secrets[:32]
    rsa_private_key = serialization.load_pem_private_key(secrets[32:], password=None, backend=default_backend())

    # Encrypt firmware with AES-GCM
    aes_gcm_iv = os.urandom(12)
    aes_gcm = Cipher(algorithms.AES(aes_key), modes.GCM(aes_gcm_iv), backend=default_backend()).encryptor()
    ciphertext = aes_gcm.update(firmware_and_message) + aes_gcm.finalize()

    # Encrypt AES-GCM IV with RSA public key
    rsa_cipher = rsa_private_key.public_key().encrypt(aes_gcm_iv, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

    # Create the final protected firmware blob
    protected_firmware_blob = metadata + rsa_cipher + ciphertext + firmware_hash
    
    # Append firmware and message to metadata
    firmware_blob = metadata + firmware_and_message

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
