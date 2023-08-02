#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time
import socket

from util import *

from pwn import p16, u16
from Crypto.Util.Padding import pad
from Crypto.Hash import SHA256

RESP_OK = b"\x00"
FRAME_SIZE = 256


def send_metadata(ser, metadata, debug=False):
    version, size = struct.unpack_from("<HH", metadata)
    #version and size will already be in little endian 
    print(f"Version: {version}\nSize: {size} bytes\n")
    version = bytes(version)
    size = bytes(size)
    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass
    # Send size and version to bootloader.
    if debug:
        print(metadata)

    ser.write(version)
    ser.write(size)

    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(p16(1,endian = "little"))
    checksum = 0
    ser.write(frame)  # Write the frame...
    frame = frame[2:]
    if debug:
        print(len(frame))
    
    for i in range (len(frame)):
        checksum+=frame[i]
    hash = SHA256.new()
    hash.update(bytes(str(checksum),encoding = 'utf8'))
    hashed_checksum = hash.digest()
    ser.write(hashed_checksum)
    if debug:
        print(len(hashed_checksum))
    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        all_data = fp.read()
    size = all_data[:2]
    version = all_data[2:4]
    msg_size = all_data[4:6]
    msg_size_int = u16(msg_size, endianness = 'little')
    msg = all_data[6:6+msg_size_int]
    iv = all_data[-16:]
    data_to_send = all_data[6+msg_size_int:-16] # -16 for tag, -12 for nonce
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass
    print("Writing Size")
    ser.write(size)
    print("Writing Metadata")
    ser.write(version)
    ser.write(msg_size)
    ser.write(msg)
    ser.write(iv)
    print("Writing firmware.")
    print(len(data_to_send))
    for idx, frame_start in enumerate(range(0, len(data_to_send), FRAME_SIZE)):
        data = data_to_send[frame_start : frame_start + FRAME_SIZE]

        # Get length of data.
        length = len(data)
        frame_fmt = ">H{}s".format(length)

        # Construct frame.
        frame = struct.pack(frame_fmt, length, data)
        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(p16(1,endian = "little"))
    ser.write(struct.pack(">H", 0x0000))
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")

    return ser




def send_metadata_default(ser, metadata, debug=False):
    version, size = struct.unpack_from("<HH", metadata)
    print(f"Version: {version}\nSize: {size} bytes\n")

    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass

    # Send size and version to bootloader.
    if debug:
        print(metadata)

    ser.write(metadata)

    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame_default(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))


def update_default(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    metadata = firmware_blob[:4]
    firmware = firmware_blob[4:]

    send_metadata(ser, metadata, debug=debug)

    for idx, frame_start in enumerate(range(0, len(firmware), FRAME_SIZE)):
        data = firmware[frame_start : frame_start + FRAME_SIZE ]

        # Get length of data.
        length = len(data)
        frame_fmt = ">H{}s".format(length)

        # Construct frame.
        frame = struct.pack(frame_fmt, length, data)

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(struct.pack(">H", 0x0000))
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")

    return ser


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    uart0_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart0_sock.connect(UART0_PATH)

    time.sleep(0.2)  # QEMU takes a moment to open the next socket

    uart1_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart1_sock.connect(UART1_PATH)
    uart1 = DomainSocketSerial(uart1_sock)

    time.sleep(0.2)

    uart2_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart2_sock.connect(UART2_PATH)

    # Close unused UARTs (if we leave these open it will hang)
    uart2_sock.close()
    uart0_sock.close()

    update(ser=uart1, infile=args.firmware, debug=args.debug)

    uart1_sock.close()


#U
#<-                       #U
#                         #load_firmware()
#SIZE
#LOOP
    #1
    #DATA256   
    #<-                       #OK
#0 length frame