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
import string
import secrets

from Crypto.Random import get_random_bytes

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
    
    gcmkey = []
    cbckey = []

    for i in range(32):
        gcmkey.append(''.join(secrets.choice(string.ascii_letters + string.digits + '~!@#$%^&*()_+=_{[]}|"/.,')))
        cbckey.append(''.join(secrets.choice(string.ascii_letters + string.digits + '~!@#$%^&*()_+=_{[]}|"/.,')))

    currentpath = os.path.realpath(__file__)
    path = os.path.join(os.path.dirname(currentpath), 'secret_build_output.txt')

    open(path, "w").close() #clears secret_build_output.txt
    file = open(path, 'w') #opens secret_build_output.txt
    for x in cbckey: #writes cbckey to secret_build_output.txt
        file.write(x)
    file.write('\n')
    for x in gcmkey: #writes gcmkey to secret_build_output.txt
        file.write(x)
    file.close #closes "secret_build_output.txt"

    currentpath = os.path.realpath(__file__)
    dir = os.path.dirname(currentpath)
    dir = dir.replace('tools', 'bootloader')
    path = os.path.join(dir, 'src', 'bootloader_secrets.h')

    open(path, 'w').close()
    file = open(path, 'w')
    file.write("#ifndef main.h\n#define bootloader_secrets.h\n")
    file.write('const char cbckey[] = {') #writes cbc key to the header file with "C" syntax
    for x in cbckey:
        file.write('\'')
        file.write(x)
        file.write('\',')
    file.write('};')
    file.write('\n')
    file.write('const char gcmkey[] = {') #writes gcm key to the header file with "C" syntax
    for x in gcmkey:
        file.write('\'')
        file.write(x)
        file.write('\',')
    file.write('};\n')
    file.write("#endif")
    file.close()

    copy_initial_firmware(firmware_path)
    make_bootloader()
