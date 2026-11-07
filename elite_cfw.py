#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
elite-cfw  -  Custom-firmware patcher for the Xiaomi Electric Scooter Elite
             (controller MCU, Nations N32G430, "Leqi"/mi5elite family).

Patches ONE specific stock firmware version (see STOCK_SHA256) to add:
  * Speed toggle  : hold BRAKE + THROTTLE together (one tap) to toggle the
                    speed cap between 25 km/h and 40 km/h. Edge-detected, so
                    one press = one toggle. The state is kept in RAM and
                    behaves like a switch (persists across power cycles - this
                    controller does not cold-clear its RAM on the power button).
  * Conditional zero-start : when UNLOCKED (40), kick-start is disabled so the
                    motor drives from a standstill; when LOCKED (25), the stock
                    kick-start behaviour is kept.
  * Region cap    : raised to 50 km/h so the 40 km/h state is not actively braked.

Self-contained: standard library only. Reverse-engineered by Fer + Claude.
License: CC BY-NC-SA 4.0  (same as ScooterTeam's bw-patcher, which this builds on).

USAGE:
    python3 elite_cfw.py stock.bin -o elite_cfw.bin

Then flash elite_cfw.bin to the controller over UART with bw-flasher
(or any Leqi/N32 UART flasher). KEEP A BACKUP of your stock firmware.
"""
import argparse, hashlib, struct, sys

KEY            = 0xAA         # XOR stream cipher key
HEADER_LEN     = 0x80        # full image header length
EU1_SIZE_OFF   = 0x0E        # uint16 LE: encrypted body size (from "EU1\0" header)
CRC_START      = 0x40        # CRC-16 is computed over body[CRC_START : fw_size-2]
CRC16_POLY     = 0x8005

# SHA-256 of the DECRYPTED stock body this patcher is written for.
# (Xiaomi Scooter Elite, controller MCU 0.1.2.0 EU1)
STOCK_SHA256   = "017d2e67515919d52962c26ac70b790977c3acd391b2a31444861ec0814c503c"

# (body_offset, expected_stock_bytes, new_bytes) - verified before applying.
PATCHES = [
    # parser_speed_hijack  (flash 0x08003C18)
    (0x1C58, bytes.fromhex("98f805005349"), bytes.fromhex("51480078dce1")),
    # speed_limit_fix_and_trampoline  (flash 0x08003FD6)
    (0x2016, bytes.fromhex("16d00bdca7f6"), bytes.fromhex("3fe007f09eba")),
    # region_cap_50kmh  (flash 0x08004058)
    (0x2098, bytes.fromhex("4ff4af70"), bytes.fromhex("40f2f410")),
    # kickstart_conditional_hook  (flash 0x08008C14)
    (0x6C54, bytes.fromhex("1578164a"), bytes.fromhex("02f0b6bc")),
    # injected_blocks_toggle_and_kickstart  (flash 0x0800B518)
    (0x9558, bytes.fromhex("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), bytes.fromhex("40f2a411c2f2000143f60072c2f20002138845f6b120834203d01080002050809080002340f23550c2f200000078502807d340f23650c2f2000000783c2800d301239088002b05d0002803d1508880f00100508093805088002803d040f29010f8f754bb98f80500f8f74dbb157840f25e12c2f2000243f60274c2f2000424880cb140f26403fdf73bbb")),
]

def xor(b):  return bytes(x ^ KEY for x in b)

def _rev8(v):
    r=0
    for i in range(8):
        if v&(1<<i): r|=1<<(7-i)
    return r&0xFF
def _rev16(v):
    r=0
    for i in range(16):
        if v&(1<<i): r|=1<<(15-i)
    return r&0xFFFF
def crc16(data):
    crc=0xFFFF
    for byte in data:
        crc ^= _rev8(byte)<<8
        for _ in range(8):
            crc = ((crc<<1)^CRC16_POLY)&0xFFFF if crc&0x8000 else (crc&0x7FFF)<<1
    return _rev16(crc)

def patch(image: bytes) -> bytes:
    if len(image) < HEADER_LEN+0x42:
        sys.exit("error: file too small to be a full firmware image")
    if image[0x0A:0x0E] != b"EU1\x00":
        sys.exit("error: no 'EU1' header tag - not a Scooter Elite full image")
    fw_size = struct.unpack_from("<H", image, EU1_SIZE_OFF)[0]
    header, enc_body = image[:HEADER_LEN], image[HEADER_LEN:]
    body = bytearray(xor(enc_body))

    got = hashlib.sha256(bytes(body)).hexdigest()
    if got != STOCK_SHA256:
        sys.exit("error: stock firmware does not match the version this patcher "
                 "targets.\n  expected SHA-256 {}\n  got      {}\n"
                 "This patcher is for ONE specific stock version. Do not use it on "
                 "another firmware.".format(STOCK_SHA256, got))

    for off, expect, new in PATCHES:
        cur = bytes(body[off:off+len(expect)])
        if cur != expect:
            sys.exit("error: unexpected bytes at 0x{:X} (expected {}, found {}). "
                     "Aborting to avoid corruption.".format(off, expect.hex(), cur.hex()))
        body[off:off+len(new)] = new

    # Re-encrypt, then compute the CRC-16 over the ENCRYPTED body
    # [CRC_START : fw_size-2] and store it big-endian at fw_size-2.
    enc = bytearray(xor(bytes(body)))
    crc = crc16(bytes(enc[CRC_START:fw_size-2]))
    enc[fw_size-2:fw_size] = struct.pack(">H", crc)

    return header + bytes(enc)

def main():
    ap=argparse.ArgumentParser(description="Patch stock Xiaomi Scooter Elite controller FW to the Elite CFW.")
    ap.add_argument("stock", help="stock controller firmware (e.g. mcu_xiaomi.scooter.elite.bin)")
    ap.add_argument("-o","--output", default="elite_cfw.bin", help="output file (default: elite_cfw.bin)")
    a=ap.parse_args()
    with open(a.stock,"rb") as f: img=f.read()
    out=patch(img)
    with open(a.output,"wb") as f: f.write(out)
    print("OK -> {}  ({} bytes)".format(a.output,len(out)))
    print("Flash over UART with bw-flasher. Keep your stock backup. Ride responsibly.")

if __name__=="__main__":
    main()
