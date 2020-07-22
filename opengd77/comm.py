"""
Copyright (C) 2020  LZ1CK, Kiril Zyapkov

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

from functools import wraps
from contextlib import contextmanager
import struct
import logging

import serial

from .codeplug import Codeplug, MemType

MAX_TRANSFER_SIZE = 32
FLASH_BLOCK_SIZE = 4096

log = logging.getLogger(__name__)

__all__ = [
    'OpenGD77ProtocolError',
    'OpenGD77Radio',
]

class OpenGD77ProtocolError(Exception): pass

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
        assert len(req_bytes)
        req = bytearray(b'C')
        req.extend(req_bytes)
        leftover = self.port.read_all()
        if len(leftover):
            log.warning(f"found bytes in serial buffer: {leftover}")
        self.port.write(req)

        with self.serial_timeout(timeout):
            resp = self.port.read(1)

        if len(resp) != 1 or resp[0] != ord('-'):
            log.warning(f"No ack for cmd {req[1]}")
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

    def _command(self, subcommand):
        req = bytearray((6, subcommand))
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
            offset += got_bytes

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
            raise OpenGD77ProtocolError("wanted 2 bytes")

        if resp != bytes(req[:2]):
            raise OpenGD77ProtocolError("W load resp mismatch {resp} {bytes(req[:2])}")
        log.debug(f"W loaded sector 0x{data_sector:04x}")

    def _W_upload_data(self, addr, data):
        total = len(data)
        remaining = len(data)
        data_pos = 0
        while remaining:
            this_len = min(remaining, MAX_TRANSFER_SIZE)
            req = bytearray(struct.pack(">BBIH", ord('W'), 2, addr, this_len))
            assert len(req) == 8
            req.extend(data[data_pos : data_pos+this_len])

            self.port.write(req)
            resp = self.port.read(2)

            if len(resp) != 2 or resp != bytes(req[:2]):
                raise OpenGD77ProtocolError(f"WU @0x{addr:x} resp={resp} want {bytes(req[:2])}")

            log.debug(f"uploaded {this_len} bytes @0x{addr:x} (data@0x{data_pos:x})")
            remaining -= this_len
            addr += this_len
            data_pos += this_len

        return total


    def _W_write_sector(self):
        req = bytearray((ord('W'), 3))
        self.port.write(req)
        resp = self.port.read(2)
        if len(resp) != 2 or resp != bytes(req):
            raise OpenGD77ProtocolError("bad W sector")
        log.debug(f"W wrote flash sector!")

    def _write_flash(self, data, addr):
        if addr % FLASH_BLOCK_SIZE != 0:
            log.error(f"{addr} not aligned")
            return False

        remaining = len(data)
        sector_addr = addr
        data_pos = 0
        while remaining > 0:
            sector_len = min(remaining, FLASH_BLOCK_SIZE)
            log.debug(f"writing F sector @0x{sector_addr:x} data 0x{data_pos} {sector_len} bytes")
            self._W_load_sector(sector_addr)
            self._W_upload_data(sector_addr, data[data_pos : data_pos+sector_len])
            self._W_write_sector()
            log.debug(f"DONE  W F sector @0x{sector_addr:x} data @0x{data_pos:x} {sector_len} bytes")
            sector_addr += sector_len
            data_pos += sector_len
            remaining -= sector_len

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

    def _write_eeprom(self, data, addr):
        remaining = len(data)
        chunk_addr = addr
        while remaining:
            wrote = self._W_eeprom_chunk(data[-remaining:], chunk_addr)
            log.debug(f"wrote E chunk @0x{chunk_addr} {wrote} bytes")
            remaining -= wrote
            chunk_addr += wrote

    def _write_memory(self, memtype, data, addr):
        if memtype == MemType.EEPROM:
            return self._write_eeprom(data, addr)
        elif memtype == MemType.FLASH:
            return self._write_flash(data, addr)
        else:
            raise OpenGD77ProtocolError(f"unsupported {memtype}")

    @require_port_session
    def write_codeplug(self, cp: Codeplug):

        self._show_screen((b"CPS", b"WRITING", b"Codeplug"))
        self._flash_red()
        self._save()

        for p in cp.parts:
            mtype = 'F' if p.memtype == MemType.FLASH else 'E'
            log.debug((f"{mtype} file  start-end=0x{p.file_addr:06x}-0x{p.file_addr+p.size:06x} "
                       f"{mtype} radio start-end=0x{p.radio_addr:06x}-0x{p.radio_addr+p.size:06x}"))

            self._write_memory(p.memtype,
                               cp.data[p.file_addr : p.file_addr + p.size],
                               p.radio_addr)

            log.info((f"write {mtype} 0x{p.file_addr:06x} "
                      f"- 0x{p.file_addr+p.size:06x} "
                      f" dest=0x{p.radio_addr:05x} "
                      f"len=0x{p.size:04x}"))

        self._save()
        self._save_and_reboot()
