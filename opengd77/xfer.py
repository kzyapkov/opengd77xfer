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
import logging
import os
import platform
import struct
import sys
import time
from collections import namedtuple  # XXX: maybe replace with dataclass?
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime

import serial

from .codeplug import Channel, Codeplug, Contact, MemType, TGList, Zone

MAX_TRANSFER_SIZE = 32
FLASH_BLOCK_SIZE = 4096

log = logging.getLogger(__name__)


def get_parsers():
    p = argparse.ArgumentParser()

    # TODO: use usb to find the correct serial port or list matching
    # ports by VID:PID, like dmrconfig does
    p.add_argument('--port', '-p', help="Serial port of radio",
                   default=('COM13'
                        if platform.system() == 'Windows'
                        else '/dev/ttyACM0'))

    p.add_argument('-v', '--verbose', default=False, action='store_true')

    # def add_file_arg(p, default=None, help="")
    #     p.add_argument('file', help=help, default=default)

    sp = p.add_subparsers(dest='cmd')

    p_read_codeplug = sp.add_parser('read', help="Read codeplug from radio")
    p_read_codeplug.add_argument(
        'file', help="Where to store codeplug from radio",
        default="codeplug.g77")

    p_write_codeplug = sp.add_parser('write', help="Write codeplug to radio")
    p_write_codeplug.add_argument(
        'file', help="Codeplug file to load into radio",
        default="codeplug.g77")

    p_backup_calib = sp.add_parser('backup_calib', help="Backup calibration data")
    p_backup_calib.add_argument(
        'file', help="Where to store calibration data")

    p_restore_calib = sp.add_parser('restore_calib', help="Restore calibration data")
    p_restore_calib.add_argument(
        'file', help="Where to get calibration from")

    p_backup_eeprom = sp.add_parser('backup_eeprom', help="Backup calibration data")
    p_backup_eeprom.add_argument(
        'file', help="Where to store EEPROM data")

    p_restore_eeprom = sp.add_parser('restore_eeprom', help="Restore calibration data")
    p_restore_eeprom.add_argument(
        'file', help="Where to get EEPROM from")




    p_dump_codeplug = sp.add_parser('dump', help="Debug helper!")
    p_dump_codeplug.add_argument(
        'file', help="File to read from",
        nargs="?")

    return p, sp


class OpenGD77ProtocolError(Exception): pass
from functools import wraps

class OpenGD77Radio(object):

    def require_port_session(f):
        @wraps(f)
        def wrapper(self, *args, **kwds):
            with self.port_session():
                return f(self, *args, **kwds)
        return wrapper

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

        if self.port.is_open:
            self.port.close()

        self._session_in_progress = False

    @contextmanager
    def serial_timeout(self, timeout):
        if timeout == self.port.timeout:
            yield self.port
            return

        t, self.port.timeout = self.port.timeout, timeout
        yield self.port
        self.port.timeout = t

    @contextmanager
    def port_session(self):
        if self._session_in_progress:
            yield self.port
            return

        self._session_in_progress = True
        try:
            self.port.open()
            yield self.port
        finally:
            self.port.close()
            self._session_in_progress = False

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

    def _C_scr_show(self):
        self._send_C(bytearray((0, )))

    def _C_scr_clear(self):
        self._send_C(bytearray((1, )))

    def _C_scr_put_text(self, x, y, size, align, invert, message):
        req = bytearray((2, x, y, size, align, invert,))
        req.extend(message[:16])
        self._send_C(req)

    def _C_scr_render(self):
        self._send_C(bytearray((3, )))

    def _C_scr_backlight(self):
        self._send_C(bytearray((4, )))

    def _C_scr_close(self):
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
        self._C_scr_show()
        self._C_scr_clear()
        for i, l in enumerate(lines[:3]):
            self._C_scr_put_text(0,  16*i, 3, 1, 0, l)
        self._C_scr_render()

    def _R_memory_chunk(self, mode, addr: int, length: int):
        if length > MAX_TRANSFER_SIZE:
            length = MAX_TRANSFER_SIZE

        req = struct.pack(">BBIH", ord('R'), int(mode), int(addr), int(length))
        self.port.write(req)
        with self.serial_timeout(.5):
            resp = self.port.read(3)

        if len(resp) != 3:
            raise OpenGD77ProtocolError()

        (c, got_len) = struct.unpack(">BH", resp)
        if got_len != length:
            log.warning(f"requested {length} bytes, but expecting {got_len}")
            # raise OpenGD77ProtocolError()

        with self.serial_timeout(3):
            data = self.port.read(got_len)

        if len(data) != got_len:
            raise OpenGD77ProtocolError(
                    f"read {len(data)} bytes but expected {got_len}")

        return data

    def _read_memory(self, memtype, addr: int, length: int):
        buf = bytearray()
        offset = 0
        bytes_left = length
        while bytes_left:
            data = self._R_memory_chunk(memtype, addr+offset, length)
            got_bytes = len(data)
            buf.extend(data)
            bytes_left -= got_bytes
            addr += got_bytes

        return buf

    @require_port_session
    def read_codeplug(self) -> Codeplug:
        """Load Codeplug data from radio"""

        self._show_screen((b"CPS", b"Reading", b"Codeplug"))
        self._flash_green()
        self._save()

        cp = Codeplug()
        try:
            for p in cp.parts:
                pd = self._read_memory(p.memtype, p.radio_addr, p.size)
                cp.data[p.file_addr : p.file_addr+p.size] = pd

                log.info((f"read    0x{p.radio_addr:06x} "
                          f"- 0x{p.radio_addr+p.size:06x} "
                          f" dest=0x{p.file_addr:06x} "
                          f"len=0x{p.size:05x}"))
        finally:
            self._C_scr_close()

        return cp

    @require_port_session
    def read_calibration(self):
        self._show_screen((b"CPS", b"Reading", b"Calibration"))
        self._flash_green()
        self._save()

        p = Codeplug.calibration
        try:
            return self._read_memory(p.memtype, p.radio_addr, p.size)
        finally:
            self._C_scr_close()

    @require_port_session
    def read_eeprom(self):
        self._show_screen((b"CPS", b"Reading", b"EEPROM"))
        self._flash_green()
        self._save()

        p = Codeplug.eeprom
        try:
            return self._read_memory(p.memtype, p.radio_addr, p.size)
        finally:
            self._C_scr_close()


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

    # def _write_flash(self, buf, bufStart, radioStart, length):
    def _write_flash(self, data, addr, length=0):
        if addr % FLASH_BLOCK_SIZE != 0:
            log.error(f"{addr} not aligned")
            return False

        remaining = len(data) if length <= 0 else length
        chunk_addr = addr
        while remaining > 0:
            batch = min(remaining, FLASH_BLOCK_SIZE)
            self._W_load_sector(chunk_addr)
            self._W_upload_data(chunk_addr, data[chunk_addr:chunk_addr+batch])
            self._W_write_sector()
            chunk_addr += batch
            remaining -= batch

        return True

    def _W_eeprom_chunk(self, data, addr):
        length = min(len(data), MAX_TRANSFER_SIZE)
        req = bytearray(struct.pack(">BBIH", ord('W'), 4, addr, length))
        req.extend(data[:length])
        self.port.write(req)
        resp = self.port.read(2)
        if len(resp) != 2 or resp != bytes(req[:2]):
            raise OpenGD77ProtocolError(f"W E @{addr:x}")
        return length

    def _write_eeprom(self, data, addr, length=0):
        remaining = len(data) if length <= 0 else length
        chunk_addr = addr
        while remaining:
            wrote = self._W_eeprom_chunk(data[-remaining:], chunk_addr)
            remaining -= wrote
            chunk_addr += wrote

    def _write_memory(self, memtype, data, addr, length=0):
        if memtype == MemType.EEPROM:
            return self._write_eeprom(data, addr, length)
        elif memtype == MemType.FLASH:
            return self._write_flash(data, addr, length) # TODO

    @require_port_session
    def write_codeplug(self, cp: Codeplug):

        self._show_screen((b"CPS", b"WRITING", b"Codeplug"))
        self._flash_red()
        self._save()

        for p in cp.parts:
            self._write_memory(p.memtype,
                               cp.data[p.file_addr : p.file_addr + p.size],
                               p.radio_addr, length=p.size)

            log.info((f"write    0x{p.radio_addr:06x} "
                      f"- 0x{p.radio_addr+p.size:06x} "
                      f" dest=0x{p.file_addr:05x} "
                      f"len=0x{p.size:04x}"))

        self._save()
        self._save_and_reboot()


def main():

    parser, subparsers = get_parsers()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        stream=sys.stdout, format="%(asctime)-15s %(filename)s:%(lineno)d %(message)s")

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
        log.info(f"Writing codeplug from {args.file} into {args.port}")
        with open(args.file, 'rb') as f:
            data = f.read()

        cp = Codeplug(data)
        radio = OpenGD77Radio(args.port)
        radio.write_codeplug(cp)

    elif args.cmd == 'dump':

        Codeplug.dump_parts()

        if args.file and os.path.exists(args.file):
            log.info(f"Loading codeplug from {args.file}")
            with open(args.file, 'rb') as f:
                data = f.read()
            cp = Codeplug()
            cp.data = bytearray(data)
        else:
            log.info(f"Loading codeplug radio at {args.port}")
            radio = OpenGD77Radio(args.port)
            cp = radio.read_codeplug()

        log.info(f"Loaded {len(cp)} bytes")

        def dump_seq(seq, name):
            log.info(f"*** {name} ***")
            for i in seq:
                log.info(f"{i.index}\t{i}")

        dump_seq(cp.contacts, "Contacts")
        dump_seq(cp.talk_groups, "Talk Groups")
        dump_seq(cp.channels, "Channels")
        dump_seq(cp.zones, f"Zones: {len(cp.zones)}")

        log.info(f"zone bits: {cp.zones.zbits.hex()}")
        log.info(f"channels per zone: {cp.zones.ch_per_zone}")


    elif args.cmd == 'backup_calib':
        if not args.file.endswith('.g77calib'):
            args.file = f"{args.file}.g77calib"
        log.info(f"Storing calibration from {args.port} to {args.file}")
        radio = OpenGD77Radio(args.port)
        data = radio.read_calibration()
        with open(args.file, 'wb') as f:
            f.write(data)

    elif args.cmd == 'backup_eeprom':
        if not args.file.endswith('.g77eeprom'):
            args.file = f"{args.file}.g77eeprom"
        log.info(f"Storing EEPROM from {args.port} to {args.file}")
        radio = OpenGD77Radio(args.port)
        data = radio.read_eeprom()
        with open(args.file, 'wb') as f:
            f.write(data)

    else:
        log.warning(f"not implemented: {args.cmd}")


if __name__ == '__main__':
    main()
