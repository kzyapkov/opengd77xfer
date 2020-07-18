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

import logging
import struct
from collections import namedtuple
from dataclasses import dataclass
from enum import IntEnum
from itertools import repeat
from typing import List
from functools import cached_property
log = logging.getLogger(__name__)


def bcd2int(buf, big_endian=False):
    if isinstance(buf, int):
        buf = (buf, )
    res = 0
    if big_endian:
        buf = reversed(buf)
    for i, b in enumerate(buf):
        res += (((b>>4) & 0x0f) * 10 + (b & 0x0f)) * (100 ** i)
    return res


class MemType(IntEnum):
    FLASH = 1
    EEPROM = 2
    MCU_ROM = 5
    DISPLAY_BUFFER = 6
    WAV_BUFFER = 7
    COMPRESSED_AMBE_BUFFER = 8


@dataclass
class Contact:
    name: bytes
    id: int
    ctype: int
    rx_tone: int
    ring_style: int
    used: int

    index: int = -1

    @classmethod
    def from_buffer(cls, buf):
        assert(len(buf) == 24)
        name = bytes(buf[:16]).strip(b'\xff').strip(b'\0')
        if not len(name):
            return None
        id = bcd2int(buf[16:20], True)
        ctype = buf[20]
        rx_tone = buf[21]
        ring_style = buf[22]
        # used = True if buf[23] == 0xff else False
        used = buf[23]
        return cls(name, id, ctype, rx_tone, ring_style, used)


@dataclass
class TGList:
    name: bytes
    contact_numbers: List[int]

    index: int = -1

    @classmethod
    def from_buffer(cls, buf):
        assert len(buf) == 80
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
        if not len(name):
            return None
        contacts = []
        for ci in range(16):
            start = 16 + ci*2
            end = start + 2
            cn = struct.unpack("<H", buf[start:end])[0]
            if cn:
                contacts.append(cn)

        return cls(name, contacts)


@dataclass
class Channel:
    name: bytes
    rx_freq: int    # Hz
    tx_freq: int    # Hz
    mode: int       # 1=digital 0=analog
    rx_ref_freq: int
    tx_ref_freq: int
    tot: int        # 15 second increments
    tot_rekey: int  # seconds
    admit: int
    rssi_threshold: int
    scanlist_index: int
    rx_tone: int
    tx_tone: int
    voice_emphasis: int
    tx_sig: int
    unmute_rule: int
    rx_sig: int
    arts_interval: int
    encrypt: int
    rx_color: int
    rx_grouplist: int
    tx_color: int
    emergency_system: int
    contact_num: int
    flag1: int
    flag2: int
    flag3: int
    flag4: int # bits... 0x80 = Power, 0x40 = Vox, 0x20 = AutoScan, 0x10 = LoneWoker, 0x08 = AllowTalkaround, 0x04 = OnlyRx, 0x02 = Channel width, 0x01 = Squelch
    vfo_offset: int
    vfo_flag: int
    sql: int

    index: int = -1

    @property
    def num(self):
        if index >= 0:
            return index + 1
        return 0

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
        if not len(name):
            return None
        rx_freq = bcd2int(buf[16:20]) * 10
        tx_freq = bcd2int(buf[20:24]) * 10
        mode = buf[24]
        rx_ref_freq = buf[25]
        tx_ref_freq = buf[26]
        tot = buf[27]
        tot_rekey = buf[28]
        admit = buf[29]
        rssi_threshold = buf[30]
        scanlist_index = buf[31]
        rx_tone = bcd2int(buf[32:34])
        tx_tone = bcd2int(buf[34:36])
        voice_emphasis = buf[36]
        tx_sig = buf[37]
        unmute_rule = buf[38]
        rx_sig = buf[39]
        arts_interval = buf[40]
        encrypt = buf[41]
        rx_color = buf[42]
        rx_grouplist = buf[43]
        tx_color = buf[44]
        emergency_system = buf[45]
        contact_num = struct.unpack_from("<H", buf, 46)[0]
        flag1 = buf[48]
        flag2 = buf[49]
        flag3 = buf[50]
        flag4 = buf[51]
        vfo_offset = buf[52:54]
        vfo_flag = buf[54]
        sql = buf[55]

        return cls(name, rx_freq, tx_freq, mode, rx_ref_freq, tx_ref_freq, tot,
                   tot_rekey, admit, rssi_threshold, scanlist_index, rx_tone,
                   tx_tone, voice_emphasis, tx_sig, unmute_rule, rx_sig,
                   arts_interval, encrypt, rx_color, rx_grouplist, tx_color,
                   emergency_system, contact_num, flag1, flag2, flag3, flag4,
                   vfo_offset, vfo_flag, sql)



@dataclass
class Zone:
    name: bytes
    channel_nums: List[int]
    index: int = -1

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
        if not len(name):
            return None
        num_ch = (len(buf) - 16) // 2
        channel_nums = []
        for ci in range(num_ch):
            start = 16 + ci * 2
            end = start + 2
            cn = struct.unpack("<H", buf[start:end])[0]
            if cn:
                channel_nums.append(cn)
            else:
                break

        return cls(name, channel_nums)

@dataclass(frozen=True)
class ChunkedBlock:
    """Helper to describe and iterate over blocks of memory"""
    raw_offset: int
    preamble: int
    item_size: int
    item_count: int

    index_offset: int = 0

    @property
    def offset(self):
        return self.raw_offset + self.preamble

    @property
    def size(self):
        return self.item_count * self.item_size + self.preamble

    def chunk(self, buf, idx):
        assert idx < self.item_count
        assert len(buf) >= self.raw_offset + self.size
        addr = self.offset + idx * self.item_size
        # # log.debug(f"walk {i} 0x{addr:08x}-0x{addr+self.item_size:08x} {len(data)}")
        return buf[addr : addr+self.item_size]

    def walk(self, buf):
        for i in range(self.item_count):
            yield self.chunk(buf, i)


class BlockView:
    def __init__(self, buf, cls, /, *chunk_blocks: List[ChunkedBlock],
                 filter=None):
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)
        self.buf = buf
        self.cls = cls
        self.chunk_blocks = chunk_blocks
        if callable(filter):
            self.filter = filter

    def filter(self, chb, key, chunk):
        return True

    def _normalize_key(self, key):
        if not isinstance(key, int):
            raise KeyError("only simple indexing is supported")
        if key < 0:
            key = len(self) + key
        return key

    def __getitem__(self, key):
        key = self._normalize_key(key)
        for cbi in self.chunk_blocks:
            if key >= cbi.index_offset and key < cbi.index_offset + cbi.item_count:
                cb = cbi
                break
        else:
            raise KeyError(f"{key} out of range")

        i = key - cb.index_offset
        chunk = cb.chunk(self.buf, i)
        if not self.filter(cb, key, chunk):
            return None

        obj = self.cls.from_buffer(chunk)
        if obj is not None:
            obj.index = key + cb.index_offset
            return obj

    def __setitem__(self, key, value):
        key = self._normalize_key(key)
        log.warning(f"{self}.__setitem__({key}, {value})")

    def __delitem__(self, key):
        key = self._normalize_key(key)
        log.warning(f"{self}.__delitem__({key})")

    def __len__(self):
        return sum((b.item_count for b in self.chunk_blocks))

    def __iter__(self):
        for cb in self.chunk_blocks:
            for i in range(cb.item_count):
                item = self[i+cb.index_offset]
                if item is not None:
                    yield item


class ZonesView(BlockView):
    # def _zone_addresses(self):
    #     zb = self.blocks['zones']
    #     bitmap = self.data[zb.raw_offset:zb.raw_offset+32]
    #     for byte_i in range(32):
    #         for bit_i in range(8):
    #             if bitmap[byte_i] & (1 << bit_i):
    #                 idx = byte_i * 8 + bit_i
    #                 yield zb.offset + idx * (16 + (2 * self.ch_per_zone))

    # def zones(self):
    #     for i, za in enumerate(self._zone_addresses()):
    #         z = Zone.from_buffer(self.data[za:za + (2 * self.ch_per_zone)])
    #         z.index = i
    #         yield z

    SIZE = 32 * 8 # number of zones supported

    @cached_property
    def zblock(self):
        return self.chunk_blocks[0]

    @cached_property
    def zbits(self):
        zb = self.zblock
        return self.buf[zb.raw_offset : zb.raw_offset + 32]

    @property
    def ch_per_zone(self):
        x = self.buf[0x806f]
        if x >= 0 and x <= 4:
            return 80
        return 16

    def _find_addr_by_index(self, key: int):
        # return zb.offset + idx * (16 + (2 * self.ch_per_zone))
        zb = self.zblock
        if key >= self.SIZE:
            return None
        bits = 0
        for byte_i in range(self.SIZE):
            for bit_i in range(8):
                if self.zbits[byte_i] & (1 << bit_i):
                    bits += 1
                    if bits == key + 1:
                        idx = (byte_i * 8 + bit_i)
                        addr = zb.offset + idx * zb.item_size
                        log.debug(f"Found zone {key} at 0x{addr:06x} (slot {idx})")
                        return addr
        else:
            return None

    def __getitem__(self, key):
        if key >= len(self):
            raise KeyError(f"{key} out of range (have {len(self)})")
        addr = self._find_addr_by_index(key)
        if addr is None:
            raise KeyError(f"{key} out of range")

        chunk = self.buf[addr : addr + 16 + (2 * self.ch_per_zone)]
        z = Zone.from_buffer(chunk)
        if not z:
            log.warning(f"Failed to create zone from {bytes(chunk)}")
            return None
        z.index = key
        return z

    def __len__(self):
        return sum(bin(x).count('1') for x in self.zbits)

    def filter(self, cb, key, chunk):
        return False

    def __iter__(self):
        for i in range(len(self)):
            item = self[i]
            if item is None:
                continue
            yield item

class Codeplug:
    """
    To add:
        * radio name get/set
        * dmrid get/set
        * boot screen data
        * vfo ch get/set
        * opengd77 custom data (boot image)
    """

    SIZE = 0x20000

    blocks = {
        'scan_lists': ChunkedBlock(0x1790, 64, 88, 64),
        # 'zones': ChunkedBlock(0x8010, 32, 48/, 250),
        'zones': ChunkedBlock(0x8010, 32, 16+(2*80), 32*8), # not really ...
        'contacts': ChunkedBlock(0x17620, 0, 24, 1024),
        'tglist': ChunkedBlock(0x1d620, 0x80, 80, 76),

        # 'channels1': ChunkedBlock(0x3780, 16, 56, 128),
        # 'channels2': ChunkedBlock(0xb1c0, 0, 56, 896),
    }

    channel_blocks = [
        # EEPROM
        ChunkedBlock(0x3780, 16, 56, 128),

        # FLASH
        # region 0xb1c0 - 0xc470 contains 7 banks of channels,
        # each with a 16-byte "enable" bitfield and 128 slots 56 bytes each
        # XXX: find a way to generate this in code without a metaclass
        ChunkedBlock(0x0b1b0, 16, 56, 128, 128*1),
        ChunkedBlock(0x0cdc0, 16, 56, 128, 128*2),
        ChunkedBlock(0x0e9d0, 16, 56, 128, 128*3),
        ChunkedBlock(0x105e0, 16, 56, 128, 128*4),

        # these don't seem to be initialized, what is the limit?
        # ChunkedBlock(0x121f0, 16, 56, 128, 128*5),
        # ChunkedBlock(0x13e00, 16, 56, 128, 128*6),
        # ChunkedBlock(0x15a10, 16, 56, 128, 128*7),
    ]

    CPPart = namedtuple('CPPart',
                        ['memtype', 'file_addr', 'radio_addr', 'size'])
    parts = (
        # EEPROM in two chunks, skippint radio settings
        # XXX: support radio settings as well?
        CPPart(MemType.EEPROM, 0x00E0, 0x00E0, 0x6000-0x00e0),
        CPPart(MemType.EEPROM, 0x7500, 0x7500, 0xb000-0x7500),

        # first 44KB of eeprom in one go;
        # BEWARE: 0x6000 - 0x7500 contain radio settings
        # CPPart(MemType.EEPROM, 0x0000, 0x0000, 0xb000),

        CPPart(MemType.FLASH, 0xB000, 0x7b000, 0x13E60),
        CPPart(MemType.FLASH, 0x1EE60, 0x00000, 0x11A0),
    )

    calibration = CPPart(MemType.FLASH, 0, 0xf000, 224)
    eeprom = CPPart(MemType.EEPROM, 0, 0, 0x10000)

    @classmethod
    def from_file(cls, filename):
        with open(filename, 'rb') as f:
            return cls(f.read())

    def __init__(self, buffer=None):
        if buffer:
            if len(buffer) != self.SIZE:
                raise Exception() # TODO
            self.data = bytearray(buffer)
        else:
            self.data = bytearray(repeat(0xff, self.SIZE))

    @cached_property
    def contacts(self):
        view = BlockView(self.data, Contact,
                         self.blocks['contacts'])
        return view

    @cached_property
    def talk_groups(self):
        def ftg(tgb, key, chunk):
            table = self.data[tgb.raw_offset : tgb.raw_offset + tgb.item_count]
            if table[key] == 0:
                return False
            return True

        return BlockView(self.data, TGList, self.blocks['tglist'],
                         filter=ftg)

    @property
    def channels(self):
        def chf(chb, key, chunk):
            table = self.data[chb.raw_offset : chb.offset]
            i = key - chb.index_offset
            if (table[i // 8] >> (i % 8)) & 0x01 == 0x00:
                return False
            log.debug(f"chf True for key {key} index {i} chb {chb}")
            return True
        return BlockView(self.data, Channel, *self.channel_blocks,
                         filter=chf)

    @property
    def zones(self):
        return ZonesView(self.data, Zone, self.blocks['zones'])


    @classmethod
    def dump_parts(cls):
        def block_in_part(block: ChunkedBlock, part: cls.CPPart) -> bool:
            # start = Codeplug.radio2file(block.raw_offset)
            start = block.raw_offset
            end = start + block.size
            part_end = part.file_addr + part.size
            return start >= part.file_addr and start < part_end # and end < part_end

        log.info("-----------  CODEPLUG FILE PARTS  ------------")
        log.info(" N where t      start - end        size")
        log.info("----------------------------------------------")
        for i, p in enumerate(cls.parts):
            blocks = [bn for bn, b in cls.blocks.items() if block_in_part(b, p)]
            start = p.file_addr
            end = start + p.size
            mode = 'E' if p.memtype == MemType.EEPROM else 'f'
            log.info((f"{i: 2} file  {mode} 0x{start:08x} - 0x{end:08x} "
                       f"0x{p.size:06x}  {','.join(blocks)}"))
            if p.file_addr == p.radio_addr:
                continue
            start = p.radio_addr
            end = start + p.size
            log.info(f"{i: 2} radio {mode} 0x{start:08x} - 0x{end:08x} 0x{p.size:06x}  {','.join(blocks)}")


    @classmethod
    def radio2file(cls, addr: int) -> int:
        """Translate address from radio space to file space"""
        for p in cls.parts:
            if addr >= p.radio_addr and addr < p.radio_addr + p.size:
                offset = p.radio_addr - p.file_addr
                return addr - offset
        else:
            return addr

    def __bytes__(self):
        return bytes(self.data)

    def __str__(self):
        return str(self.data)

    def __len__(self):
        if not self.data: return 0
        return len(self.data)
