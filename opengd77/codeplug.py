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
from typing import List, Iterator
from functools import cached_property
from ruamel.yaml import yaml_object
from opengd77.binvar import *


log = logging.getLogger(__name__)


def bcd2int(buf, *, big_endian=False):
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


class IndexedBinContainer(BinContainer):
    def __init__(self, **kw):
        if 'index' not in kw:
            kw['index'] = -1
        super().__init__(**kw)

    @classmethod
    def to_yaml(cls, representer, node):
        return representer.represent_dict(node)


class Contact(IndexedBinContainer):
    SIZE = 24
    name = strvar(0, 16)
    id = bcdvar(16, 4, big_endian=True)
    ctype = structvar(20, "B", default=0)
    rx_tone = structvar(21, "B", default=0)
    ring_style = structvar(22, "B", default=0)
    used = structvar(23, "B")

    @classmethod
    def from_buffer(cls, buf):
        contact = super().from_buffer(buf)
        if contact.used > 2 or len(contact.name) == 0:
            log.debug(f"invalid contact: {contact} from 0x{buf.hex()}")
            contact.used = 0xff
            return None
        return contact

class TGList(IndexedBinContainer):
    SIZE = 80
    name = strvar(0, 16)
    contact_nums = structlist(16, "<H", 16, filter=lambda x: x > 0)

class Channel(IndexedBinContainer):
    SIZE = 56
    name = strvar(0, 16)
    rx_freq = bcdvar(16, 4, mult=10)
    tx_freq = bcdvar(20, 4, mult=10)
    mode = structvar(24, "B", default=0)
    rx_ref_freq = structvar(25, "B", default=0)         # ignored
    tx_ref_freq = structvar(26, "B", default=0)         # ignored
    tot = structvar(27, "B", default=0)
    tot_rekey = structvar(28, "B", default=5)           # ignored
    admit = structvar(29, "B", default=0)               # ignored
    rssi_threshold = structvar(30, "B", default=80)     # ignored
    scanlist_index = structvar(31, "B", default=0)      # ignored
    rx_tone = bcdvar(32, 2, default=16665)
    tx_tone = bcdvar(34, 2, default=16665)
    voice_emphasis = structvar(36, "B", default=0)      # ignored
    tx_sig = structvar(37, "B", default=0)              # ignored
    unmute_rule = structvar(38, "B", default=0)         # ignored
    rx_sig = structvar(39, "B", default=0)              # ignored
    arts_interval = structvar(40, "B", default=22)      # ignored
    encrypt = structvar(41, "B", default=0)             # ignored
    rx_color = structvar(42, "B", default=0)
    rx_grouplist = structvar(43, "B", default=0)
    tx_color = structvar(44, "B", default=0)
    emergency_system = structvar(45, "B", default=0)
    contact_num = structvar(46, "<H", default=0)
    flag1 = structvar(48, "B", default=0x00)
    flag2 = structvar(49, "B", default=0x00)
    flag3 = structvar(50, "B", default=0x00)
    flag4 = structvar(51, "B")
    vfo_offset = structvar(52, "<H", default=0)
    vfo_flag = structvar(54, "B", default=0)
    sql = structvar(55, "B", default=2)

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
        if not len(name):
            return None
        return super().from_buffer(buf)


class Zone(IndexedBinContainer):
    SIZE = 16 + 2 * 80
    name = strvar(0, 16)
    channel_nums = structlist(16, "<H", 80, filter=lambda x: x != 0)

    @property
    def number(self):
        return self.index + 1

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
        if not len(name):
            return None
        return super().from_buffer(buf)


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
        raise NotImplemented()

    def __delitem__(self, key):
        key = self._normalize_key(key)
        log.warning(f"{self}.__delitem__({key})")
        raise NotImplemented()

    def __len__(self):
        return sum((b.item_count for b in self.chunk_blocks))

    @classmethod
    def to_yaml(cls, representer, node):
        return representer.represent_list(node)

    def __iter__(self):
        for cb in self.chunk_blocks:
            for i in range(cb.item_count):
                item = self[i+cb.index_offset]
                if item is not None:
                    yield item


class ZonesView(BlockView):

    SIZE = 68

    def __init__(self, buf, cls, bounds, block: ChunkedBlock):
        super().__init__(buf, cls, block)
        self._bounds = bounds

    @cached_property
    def zblock(self):
        return self.chunk_blocks[0]

    @property
    def zbytes(self):
        zb = self.zblock
        return self.buf[zb.raw_offset : zb.raw_offset + 32]

    @property
    def ch_per_zone(self):
        x = self.buf[0x806f]
        if x >= 0 and x <= 4:
            return 80
        return 16

    @property
    def zone_size(self):
        return 16 + 2 * self.ch_per_zone

    def _find_addr_by_index(self, key: int):
        zb = self.zblock
        if key >= self.SIZE:
            return None
        bits = -1
        for byte_i in range(32):
            for bit_i in range(8):
                if self.zbytes[byte_i] & (1 << bit_i) == 0:
                    continue
                bits += 1
                if bits == key:
                    idx = (byte_i * 8 + bit_i)
                    addr = zb.offset + idx * self.zone_size
                    if addr + zb.item_size > self._bounds[1]:
                        log.warning(f"zone id {idx} out of bounds (@0x{addr})")
                        return None
                    log.debug(f"Found zone {key} at 0x{addr:06x} (slot {idx})")
                    return addr
        else:
            log.warning(f"zone idx{idx} broke out of loop?")
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
        bitstr = ''.join((f"{x:08b}" for x in self.zbytes))
        bitstr = bitstr[:self.SIZE]
        return bitstr.count('1')

        # bitcount = sum(bin(x)[:self.SIZE].count('1') for x in self.zbytes)
        # return min(bitcount, self.SIZE)

        # for i in range(self.SIZE):
        #     if self._find_addr_by_index(i) is not None:
        #         continue
        #     return i


    def filter(self, cb, key, chunk):
        return False

    def __iter__(self):
        for i in range(len(self)):
            try:
                yield self[i]
            except KeyError as e:
                return


class Codeplug:
    """
    To add:
        * radio name get/set
        * dmrid get/set
        * boot screen data
        * vfo ch get/set
        * opengd77 custom data (boot image)

        const int CODEPLUG_ADDR_USER_DMRID = 0x00E8;
        const int CODEPLUG_ADDR_USER_CALLSIGN = 0x00E0; // same as radio name

    """

    SIZE = 0x20000

    # blocks describe semantics of the binary blob
    blocks = {
        'scan_lists': ChunkedBlock(0x1790, 64, 88, 64),
        'zones': ChunkedBlock(0x8010, 32, 16+(2*80), 32*8), # special case
        'contacts': ChunkedBlock(0x17620, 0, 24, 1024),
        'tglist': ChunkedBlock(0x1d620, 0x80, 80, 76),
        # channels are listed separately
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

    # CPPart describes a chunk of memory we read or write
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
    def from_file(cls, f):
        return cls(f.read())

    def __init__(self, buffer=None):
        if buffer:
            if len(buffer) != self.SIZE:
                raise ValueError("codeplug is exactly {self.SIZE} bytes long")
            if any((x>0xff for x in buffer)):
                raise ValueError("bad data in codeplug buffer")
            self.data = bytearray(buffer)
        else:
            # XXX: bootstrap empty codeplug with a default one?
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

    def as_dict(self):
        # return {
        #     'zones': [z.as_dict() for z in self.zones],
        #     'contacts': [z.as_dict() for z in self.contacts],
        #     'channels': [z.as_dict() for z in self.channels],
        #     'talk_groups': [z.as_dict() for z in self.talk_groups],
        # }
        return {
            'user': {
                'dmr_id': self.dmr_id,
                'callsign': self.callsign
            },
            'zones': list(self.zones),
            'contacts': list(self.contacts),
            'channels': list(self.channels),
            'talk_groups': list(self.talk_groups),
        }

    @property
    def channels(self):
        def chf(chb, key, chunk):
            table = self.data[chb.raw_offset : chb.offset]
            i = key - chb.index_offset
            if (table[i // 8] >> (i % 8)) & 0x01 == 0x00:
                return False
            # log.debug(f"chf -> True for key={key} index={i} chb={chb}")
            return True
        return BlockView(self.data, Channel, *self.channel_blocks,
                         filter=chf)

    @property
    def zones(self) -> Iterator[Zone]:
        # return []
        return ZonesView(self.data, Zone, (0x7500, 0xb000), self.blocks['zones'])


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
            blocks = [f"{bn}@0x{b.raw_offset:04x}" for bn, b in cls.all_blocks() if block_in_part(b, p)]
            start = p.file_addr
            end = start + p.size
            mode = 'E' if p.memtype == MemType.EEPROM else 'f'
            log.info((f"{i: 2} file  {mode} 0x{start:08x} - 0x{end:08x} "
                       f"0x{p.size:06x}  {','.join(blocks)}"))
            if p.file_addr == p.radio_addr:
                continue
            start = p.radio_addr
            end = start + p.size
            blocks = [f"{bn}@0x{cls.file2radio(b.raw_offset):04x}" for bn, b in cls.all_blocks() if block_in_part(b, p)]
            log.info(f"{i: 2} radio {mode} 0x{start:08x} - 0x{end:08x} 0x{p.size:06x}  {','.join(blocks)}")

    @classmethod
    def all_blocks(cls):
        yield from cls.blocks.items()
        for i, chb in enumerate(cls.channel_blocks):
            yield (f"channels_{i}", chb)

    @classmethod
    def radio2file(cls, addr: int) -> int:
        """Translate address from radio space to file space"""
        for p in cls.parts:
            if addr >= p.radio_addr and addr < p.radio_addr + p.size:
                offset = p.radio_addr - p.file_addr
                return addr - offset
        else:
            return addr

    @classmethod
    def file2radio(cls, addr: int) -> int:
        """Translate address from file space to radio space"""
        for p in cls.parts:
            if addr >= p.file_addr and addr < p.file_addr + p.size:
                offset = p.file_addr - p.radio_addr
                return addr - offset
        else:
            return addr

    @property
    def dmr_id(self):
        b = self.data[0x00E8 : 0x00E8 + 4]
        return bcd2int(b, big_endian=True)

    @dmr_id.setter
    def dmr_id(self, value):
        raise NotImplemented()

    @property
    def callsign(self):
        b = self.data[0x00E0 : 0x00E0 + 8]
        return bytes(b).rstrip(b'\xff').rstrip(b'\0').decode('ascii')

    @callsign.setter
    def callsign(self):
        raise NotImplemented()

    def __bytes__(self):
        return bytes(self.data)

    def __str__(self):
        return str(self.data)

    def __len__(self):
        if not self.data: return 0
        return len(self.data)


def register_yaml(yaml):
    yaml.register_class(Contact)
    yaml.register_class(TGList)
    yaml.register_class(Channel)
    yaml.register_class(Zone)
