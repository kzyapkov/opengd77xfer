#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (C) 2020  OH1FSS juhani.jaakola@iki.fi
                    F1RMB, Daniel Caujolle-Bert <f1rmb.daniel@gmail.com>
                    VK3KYY / G4KYF, Roger Clark.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
import sys
import os
import time
import ntpath
import getopt
import serial
import platform
import argparse
import logging
import struct
from datetime import datetime
from contextlib import contextmanager
from enum import Enum
from itertools import repeat

MAX_TRANSFER_SIZE = 32

OPT_SAVE_SETTINGS_NOT_VFOS = 0
OPT_REBOOT                 = 1
OPT_SAVE_SETTINGS_AND_VFOS = 2
OPT_FLASH_GREEN_LED        = 3
OPT_FLASH_RED_LED          = 4
CODEPLUG_SIZE = 0x20000

FLASH_BLOCK_SIZE = 4096
EEPROM_SEND_SIZE = 8

log = logging.getLogger()

MODE_READ_FLASH = 1
MODE_READ_EEPROM = 2
MODE_READ_MCU_ROM = 5
MODE_READ_DISPLAY_BUFFER = 6
MODE_READ_WAV_BUFFER = 7
MODE_COMPRESS_AND_ACCESS_AMBE_BUFFER = 8


def get_parser():
    p = argparse.ArgumentParser()

    # TODO: use usb to find the correct serial port or list matching
    # ports, like dmrconfig does
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

    return p


class OpenGD77Codeplug:
    def __init__(self):
        self.data = bytearray(repeat(0xff, CODEPLUG_SIZE))
        # self.data[0x00:8] = bytearray([0x4d, 0x44, 0x2d, 0x37, 0x36, 0x30, 0x50, 0xff]) # MD-760P
        # self.data[0x80:8] = bytearray([0x00, 0x04, 0x70, 0x04, 0x36, 0x01, 0x74, 0x01]) # freqs
        # self.data[0x90:5] = bytearray([0x47, 0x44, 0x2d, 0x37, 0x37]) # GD-77
        # self.data[0xd8:8] = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # ???

    def __bytes__(self):
        return bytes(self.data)

    def __str__(self):
        return str(self.data)

class OpenGD77ProtocolError(Exception): pass

class OpenGD77Radio(object):

    # mode, file_offset, radio_addr, len
    codeplug_parts = (
        (MODE_READ_EEPROM, 0x00E0, 0x00E0, 0x5f20),
        (MODE_READ_EEPROM, 0x7500, 0x7500, 0x3B00),
        (MODE_READ_FLASH, 0xB000, 0x7b000,0x13E60),
        (MODE_READ_FLASH, 0x1EE60, 0x00000, 0x11A0),
    )

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
        for (mode, ofs, addr, length) in self.codeplug_parts:
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

    parser = get_parser()
    args = parser.parse_args()

    radio = OpenGD77Radio(args.port)

    if args.cmd == 'read':
        if not args.file.endswith('.g77'):
            args.file = f"{args.file}.g77"
        log.info(f"Reading codeplug from {args.port} into {args.file}")
        cp = radio.read_codeplug()
        log.info(f"Read {len(cp.data)} bytes")
        with open(args.file, 'wb') as f:
            f.write(cp.data)

    if args.cmd == 'write':
        log.info(f"Writing codeplug from {args.file} into {args.port} NOT")
        with open(args.file, 'r') as f:
            data = f.read()


        # setConfig(ser, args.file)

    # if (ser.is_open):
    #     ser.close()


if __name__ == '__main__':
    main()
