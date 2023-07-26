#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )
    gcmkey = get_random_bytes(32) #generates new, randomly generated 32 byte AES key for GCM
    cbckey = get_random_bytes(32) #generates new, randomly generated 32 byte AES key for CBC

    open("secret_build_output.txt", "w").close() #clears secret_build_output.txt
    file = open('secret_build_output.txt', 'w') #opens secret_build_output.txt
    file.write(cbckey) #writes AES key "secret_build_output.txt"
    file.write('\n')
    file.write(gcmkey)
    file.close #closes "secret_build_output.txt"

    open('main.bin', 'w').close()
    file = open('main.bin', 'w')
    file.write(gcmkey) #writes AES key to "main.bin"
    file.write('\n')
    file.write(cbckey) #writes RSA private key to "main.bin"

    copy_initial_firmware(firmware_path)
    make_bootloader()
