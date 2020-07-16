#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (C) 2020  OH1FSS, juhani.jaakola@iki.fi
                    F1RMB, Daniel Caujolle-Bert <f1rmb.daniel@gmail.com>
                    VK3KYY / G4KYF, Roger Clark
                    LZ1CK, Kiril Zyapkov

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
import argparse
import getopt
import logging
import ntpath
import os
import platform
import struct
import sys
import time
from collections import namedtuple  # XXX: maybe replace with dataclass?
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from itertools import repeat
from typing import List

import serial


MAX_TRANSFER_SIZE = 32

OPT_SAVE_SETTINGS_NOT_VFOS = 0
OPT_REBOOT                 = 1
OPT_SAVE_SETTINGS_AND_VFOS = 2
OPT_FLASH_GREEN_LED        = 3
OPT_FLASH_RED_LED          = 4

CODEPLUG_SIZE = 0x20000

FLASH_BLOCK_SIZE = 4096
EEPROM_SEND_SIZE = 8

MODE_READ_FLASH = 1
MODE_READ_EEPROM = 2
MODE_READ_MCU_ROM = 5
MODE_READ_DISPLAY_BUFFER = 6
MODE_READ_WAV_BUFFER = 7
MODE_COMPRESS_AND_ACCESS_AMBE_BUFFER = 8


log = logging.getLogger()

def bcd2int(b):
    return ((b>>4) & 0x0f) * 10 + (b & 0x0f)

def get_parsers():
    p = argparse.ArgumentParser()

    # TODO: use usb to find the correct serial port or list matching
    # ports by VID:PID, like dmrconfig does
    p.add_argument('--port', '-p', help="Serial port of radio",
                   default=('COM13'
                        if platform.system() == 'Windows'
                        else '/dev/ttyACM0'))

    sp = p.add_subparsers(dest='cmd')
    p_read_codeplug = sp.add_parser('read')
    p_read_codeplug.add_argument(
        'file', help="Where to store codeplug from radio",
        default="codeplug.g77")

    p_write_codeplug = sp.add_parser('write')
    p_write_codeplug.add_argument(
        'file', help="Codeplug file to load into radio",
        default="codeplug.g77")

    p_dump_codeplug = sp.add_parser('dump')
    p_dump_codeplug.add_argument(
        'file', help="Where to store codeplug from radio",
        nargs="?")

    return p, sp


@dataclass(frozen=True)
class ChunkedBlock:

    raw_offset: int
    preamble: int
    item_size: int
    item_count: int

    @property
    def offset(self):
        return self.raw_offset + self.preamble

    def walk(self, buf):
        for i in range(self.item_count):
            addr = self.offset + i * self.item_size
            data = buf[addr : addr+self.item_size]
            # log.debug(f"walk {i} 0x{addr:08x}-0x{addr+self.item_size:08x} {len(data)}")
            yield data


@dataclass
class Contact:
    name: str
    id: int
    ctype: int
    rx_tone: bool
    ring_style: int
    used: int

    @classmethod
    def from_buffer(cls, buf):
        name_end = min(buf.index(0xff), 15)
        name = bytes(buf[0:name_end])
        id = (bcd2int(buf[16]) * 1000000 +
              bcd2int(buf[17]) * 10000 +
              bcd2int(buf[18]) * 100 +
              bcd2int(buf[19]) * 1)
        ctype = buf[20]
        rx_tone = buf[21]
        ring_style = buf[22]
        # used = True if buf[23] == 0xff else False
        used = buf[23]
        return cls(name, id, ctype, rx_tone, ring_style, used)


@dataclass
class TGList:
    name: str
    contacts: List[int]

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16])
        name = name.strip(b'\0')
        name = name.strip(b'\xff')
        contacts = []
        for ci in range(16):
            start = 16 + ci*2
            end = start + 2
            cn = struct.unpack("<H", buf[start:end])[0]
            if cn:
                contacts.append(cn)

        return cls(name, contacts)


@dataclass
class Zone:
    name: str


@dataclass
class Channel:
    name: str

class OpenGD77Codeplug:
    """Also
       * radio name get/set
       * dmrid get/set
       * boot screen data
       * vfo ch get/set
       * opengd77 custom data (boot image)

    """

    # mode, file_offset, radio_addr, length
    parts = (
        (MODE_READ_EEPROM, 0x00E0, 0x00E0, 0x5f20),
        (MODE_READ_EEPROM, 0x7500, 0x7500, 0x3B00),
        (MODE_READ_FLASH, 0xB000, 0x7b000,0x13E60),
        (MODE_READ_FLASH, 0x1EE60, 0x00000, 0x11A0),
    )

    contacts_block =    ChunkedBlock(0x17620, 0, 24, 1024)
    tglist_block =      ChunkedBlock(0x1d620, 128, 80, 76)
    zones_block =       ChunkedBlock(0x08010, 32, 48, 250)
    scan_lists_block =  ChunkedBlock(0x01790, 64, 88, 64)
    channels1_block =   ChunkedBlock(0x03780, 16, 56, 128)
    channels2_block =   ChunkedBlock(0xb1b0, 16, 56, 896)

    @staticmethod
    def radio2file(address):
        for mode, file_offset, radio_addr, length in self.parts:
            if address >= radio_addr and address < radio_addr + length:
                offset = radio_addr - file_offset
                return address - offset
        else:
            return address

    def __init__(self):
        self.data = bytearray(repeat(0xff, CODEPLUG_SIZE))
        # self.data[0x00:8] = bytearray([0x4d, 0x44, 0x2d, 0x37, 0x36, 0x30, 0x50, 0xff]) # MD-760P
        # self.data[0x80:8] = bytearray([0x00, 0x04, 0x70, 0x04, 0x36, 0x01, 0x74, 0x01]) # freqs
        # self.data[0x90:5] = bytearray([0x47, 0x44, 0x2d, 0x37, 0x37]) # GD-77
        # self.data[0xd8:8] = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # ???

    def contacts(self):
        for chunk in self.contacts_block.walk(self.data):
            if chunk[0] == 0xff:
                continue
            c = Contact.from_buffer(chunk)
            # if c.used:
            yield c

    def talk_groups(self):
        tgb = self.tglist_block
        table = self.data[tgb.raw_offset : tgb.offset]
        print(table)
        for chunk in tgb.walk(self.data):
            tg = TGList.from_buffer(chunk)
            if not len(tg.name):
                continue
            yield tg

    def __bytes__(self):
        return bytes(self.data)

    def __str__(self):
        return str(self.data)

    def __len__(self):
        if not self.data: return 0
        return len(self.data)

class OpenGD77ProtocolError(Exception): pass

class OpenGD77Radio(object):

    def __init__(self, port):
        if port is serial.SerialBase:
            self.port = port
        else:
            self.port = serial.Serial(port)

        self.port.bytesize = serial.EIGHTBITS
        self.port.parity = serial.PARITY_NONE
        self.port.stopbits = serial.STOPBITS_ONE
        self.port.timeout = 2.0
        self.port.write_timeout = 2.0

        if not self.port.is_open:
            self.port.open()

        #     log.info("\r - {0} 0x{1:X} bytes: {2}%".format(rw,length,sofar * 100 // length), end='')
        self._update_progress = None

    @property
    def update_progress(self):
        if callable(self._update_progress):
            return self._update_progress
        return None

    @update_progress.setter
    def update_progress(self, cb):
        if callable(cb):
            self._update_progress = cb

    def _invoke_update_progress(self, progress):
        if not callable(self._update_progress):
            return
        try:
            self._update_progress(progress)
        except Exception as e:
            log.warning(f"Progress update failed: {e}")

    @contextmanager
    def serial_timeout(self, timeout):
        if timeout == self.port.timeout:
            yield self.port
            return

        t, self.port.timeout = self.port.timeout, timeout
        yield self.port
        self.port.timeout = t

    def _send_C(self, req_bytes, timeout=3.0):
        req = bytearray(b'C')
        req.extend(req_bytes)
        self.port.read_all()
        self.port.write(req)

        with self.serial_timeout(timeout):
            resp = self.port.read(1)

        if len(resp) != 1 or resp[0] != ord('-'):
            log.warning(f"No ACK byte for cmd {req[1]}")
            raise OpenGD77ProtocolError()

    def _cps_scr_show(self):
        self._send_C(bytearray((0, )))

    def _cps_scr_clear(self):
        self._send_C(bytearray((1, )))

    def _cps_scr_put_text(self, x, y, size, align, invert, message):
        req = bytearray((2, x, y, size, align, invert,))
        req.extend(message[:16])
        self._send_C(req)

    def _cps_scr_render(self):
        self._send_C(bytearray((3, )))

    def _cps_scr_backlight(self):
        self._send_C(bytearray((4, )))

    def _cps_scr_close(self):
        self._send_C(bytearray((5, )))

    def _command(self, option_number):
        req = bytearray((6, option_number))
        self._send_C(req)

    def _save_and_reboot(self):
        self._command(0)

    def _reboot(self):
        self._command(1)

    def _save(self):
        self._command(2)

    def _flash_green(self):
        self._command(3)

    def _flash_red(self):
        self._command(4)

    def _codec_init(self):
        self._command(5)

    def _sound_init(self):
        self._command(6)

    def _show_screen(self, lines):
        self._cps_scr_show()
        self._cps_scr_clear()
        for i, l in enumerate(lines[:3]):
            self._cps_scr_put_text(0,  16*i, 3, 1, 0, l)
        self._cps_scr_render()

    def _read_memory_chunk(self, mode, addr: int, length: int):
        if length > MAX_TRANSFER_SIZE:
            length = MAX_TRANSFER_SIZE

        req = struct.pack(">BBIH", ord('R'), int(mode), int(addr), int(length))
        self.port.write(req)
        with self.serial_timeout(.5):
            resp = self.port.read(3)

        if len(resp) != 3:
            log.warn(f"got {resp}")
            raise OpenGD77ProtocolError()

        (c, got_len) = struct.unpack(">BH", resp)
        if got_len != length:
            log.warn(f"wanted {length} bytes, got {got_len}")
            raise OpenGD77ProtocolError()

        with self.serial_timeout(3):
            data = self.port.read(got_len)

        if len(data) != got_len:
            log.warn(f"read {len(data)} bytes but wanted {got_len}")
            raise OpenGD77ProtocolError()

        return data


    def _read_memory(self, mode, addr: int, length: int):
        buf = bytearray()
        offset = 0
        bytes_left = length
        while bytes_left:
            data = self._read_memory_chunk(mode, addr+offset, length)
            got_bytes = len(data)
            buf.extend(data)
            bytes_left -= got_bytes
            addr += got_bytes

        # log.info(f"returning data with len={len(buf)}, wanted {length}")
        return buf

    def read_codeplug(self):
        self._show_screen((b"CPS", b"Reading", b"Codeplug"))
        self._flash_green()
        self._save()

        cp = OpenGD77Codeplug()

        # mode, file_offset, radio_addr, len
        for (mode, ofs, addr, length) in OpenGD77Codeplug.parts:
            part = self._read_memory(mode, addr, length)
            log.debug(f"read    0x{addr:08X} - 0x{addr+length:08X} len={length} / {len(part)}")
            cp.data[ofs:ofs+length] = part

        self._cps_scr_close()

        return cp

    def _W_load_sector(self, address):
        data_sector = address // 4096

        req = bytearray(5)
        req[0] = ord('W')
        req[1] = 1 # subcommand
        req[2] = (data_sector >> 16) & 0xff
        req[3] = (data_sector >>  8) & 0xff
        req[4] = (data_sector >>  0) & 0xff

        self.port.write(req)
        with self.serial_timeout(2):
            resp = self.port.read(2)

        if len(resp) != 2:
            return False
        # XXX: yada yada yada, it's fine
        return True

    def _W_upload_data(self, offset, data):
        extra = 8
        req = bytearray(extra + MAX_TRANSFER_SIZE)
        req[0] = ord('W')
        req[1] = 2

        length = len(data)
        pos = 0
        while length:
            this_len = min(length, MAX_TRANSFER_SIZE)
            req[2:extra] = struct.pack(">IH", offset, this_len)
            req[extra:] = data[pos:pos+this_len]

            self.port.write(req)
            resp = self.port.read(2)

            if len(resp) != 2 or resp != bytes(req[0:2]):
                return False

            length -= this_len
            pos += this_len

        return True

    def _W_write_sector(self):
        req = bytearray((ord('W'), 3))
        self.port.write(req)
        resp = self.port.read(2)
        return len(resp) == 2 and resp == bytes(req)

    def setFlashMemoryArea(self, buf, bufStart, radioStart, length):
        bufPos = bufStart # index in buf
        radioPos = radioStart # address in radio
        remaining = length
        if radioPos % FLASH_BLOCK_SIZE != 0:
            log.info("ERROR: radioPos "+str(radioPos)+" not aligned")
            return False
        if length == 0:
            return True

        while remaining > 0:
            batch = min(remaining, FLASH_BLOCK_SIZE)
            self._W_load_sector(radioPos)
            self._W_upload_data(buf[bufPos:bufPos+batch], radioPos, batch)
            self._W_write_sector()
            bufPos += batch
            radioPos += batch
            remaining -= batch
            self.update_progress('flashing', radioPos - radioStart,length)

        return True


    def eepromSendData(self, buf, bufStart, radioStart, length):
        snd = bytearray(EEPROM_SEND_SIZE+MAX_TRANSFER_SIZE)
        snd[0] = ord('W')
        snd[1] = 4
        bufPos = bufStart
        radioPos = radioStart
        remaining = length
        while (remaining > 0):
            batch = min(remaining,MAX_TRANSFER_SIZE)
            snd[2] = (radioPos >> 24) & 0xFF
            snd[3] = (radioPos >> 16) & 0xFF
            snd[4] = (radioPos >>  8) & 0xFF
            snd[5] = (radioPos >>  0) & 0xFF
            snd[6] = (batch >>  8) & 0xFF
            snd[7] = (batch >>  0) & 0xFF
            snd[EEPROM_SEND_SIZE:EEPROM_SEND_SIZE+batch] = buf[bufPos:bufPos+batch]
            self.port.write(snd)
            rcv = ser.read(2)
            if len(rcv) != 2 or rcv != bytes(snd):
                log.info(f"ERROR: at {radioPos}")

            bufPos += batch
            radioPos += batch
            remaining -= batch
            printProgress('eepromming',radioPos - radioStart,length)

        log.info("")
        return True


    def write_codeplug(self, codeplug):
        self._show_screen((b"CPS", b"Reading", b"Codeplug"))
        self._flash_red()
        self._save()

        self.eepromSendData(buf, 0x00E0, 0x00E0, 0x5f20)
        self.eepromSendData(buf, 0x7500, 0x7500, 0x3B00)
        self.setFlashMemoryArea(buf,  0xB000,0x7b000,0x13E60)
        self.setFlashMemoryArea(buf, 0x1EE60,0x00000, 0x11A0)
        # cmdCloseCPSScreen(ser)
        cmdCommand(ser,OPT_SAVE_SETTINGS_NOT_VFOS)


def main():
    logging.basicConfig(level=logging.DEBUG, stream=sys.stderr,
                        format="%(asctime)-15s %(message)s")

    parser, subparsers = get_parsers()
    args = parser.parse_args()

    if args.cmd not in subparsers.choices:
        log.info("No command given.")
        sys.exit(1)

    if args.cmd == 'read':
        if not args.file.endswith('.g77'):
            args.file = f"{args.file}.g77"
        log.info(f"Reading codeplug from {args.port} into {args.file}")
        radio = OpenGD77Radio(args.port)
        cp = radio.read_codeplug()
        log.info(f"Read {len(cp.data)} bytes")
        with open(args.file, 'wb') as f:
            f.write(cp.data)

    elif args.cmd == 'write':

        log.error("Writing still not reworked and tested, so no.")
        sys.exit(5)

        log.info(f"Writing codeplug from {args.file} into {args.port} NOT")
        with open(args.file, 'r') as f:
            data = f.read()

    elif args.cmd == 'dump':
        if args.file and os.path.exists(args.file):
            log.info(f"Loading codeplug from {args.file}")
            with open(args.file, 'rb') as f:
                data = f.read()
            cp = OpenGD77Codeplug()
            cp.data = bytearray(data)
        else:
            radio = OpenGD77Radio(args.port)
            cp = radio.read_codeplug()

        log.info(f"Loaded {len(cp)} bytes")

        for c in cp.contacts():
            log.info(f"Contact {c}")

        for tg in cp.talk_groups():
            log.info(f"TG {tg}")

    else:
        log.warning(f"not implemented: {args.cmd}")


if __name__ == '__main__':
    main()
