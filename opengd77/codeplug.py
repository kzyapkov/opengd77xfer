import logging
import struct
from collections import namedtuple
from dataclasses import dataclass
from enum import IntEnum
from itertools import repeat
from typing import List

log = logging.getLogger(__name__)


def bcd2int(b):
    return ((b>>4) & 0x0f) * 10 + (b & 0x0f)


class MemType(IntEnum):
    FLASH = 1
    EEPROM = 2

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
    name: bytes
    contact_numbers: List[int]

    index: int = -1

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
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
    contact: int
    flag1: int
    flag2: int
    flag3: int
    flag4: int # bits... 0x80 = Power, 0x40 = Vox, 0x20 = AutoScan, 0x10 = LoneWoker, 0x08 = AllowTalkaround, 0x04 = OnlyRx, 0x02 = Channel width, 0x01 = Squelch
    vfo_offset: int
    vfo_flag: int
    sql: int

    index: int = -1

    @classmethod
    def from_buffer(cls, buf):
        name = bytes(buf[:16]).strip(b'\0').strip(b'\xff')
        rx_freq = (bcd2int(buf[16]) * 10 +
                   bcd2int(buf[17]) * 1000 +
                   bcd2int(buf[18]) * 100000 +
                   bcd2int(buf[19]) * 10000000)
        tx_freq = (bcd2int(buf[20]) * 10 +
                   bcd2int(buf[21]) * 1000 +
                   bcd2int(buf[22]) * 100000 +
                   bcd2int(buf[23]) * 10000000)
        mode = buf[24]
        rx_ref_freq = buf[25]
        tx_ref_freq = buf[26]
        tot = buf[27]
        tot_rekey = buf[28]
        admit = buf[29]
        rssi_threshold = buf[30]
        scanlist_index = buf[31]
        rx_tone = buf[32:34] # TODO: BCD
        tx_tone = buf[34:36]
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
        contact = buf[46:48] # TODO: LE integer
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
                   emergency_system, contact, flag1, flag2, flag3, flag4,
                   vfo_offset, vfo_flag, sql)



@dataclass
class Zone:
    name: bytes

    index: int = -1

    @classmethod
    def from_buffer(cls, buf):
        return cls()


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

    @dataclass(frozen=True)
    class ChunkedBlock:
        """Helper to describe and iterate over blocks of memory"""
        raw_offset: int
        preamble: int
        item_size: int
        item_count: int

        @property
        def offset(self):
            return self.raw_offset + self.preamble

        @property
        def size(self):
            return self.item_count * self.item_size + self.preamble

        def walk(self, buf):
            for i in range(self.item_count):
                addr = self.offset + i * self.item_size
                data = buf[addr : addr+self.item_size]
                # log.debug(f"walk {i} 0x{addr:08x}-0x{addr+self.item_size:08x} {len(data)}")
                yield data

    blocks = {
        'scan_lists': ChunkedBlock(0x1790, 64, 88, 64),
        'zones': ChunkedBlock(0x8010, 32, 48, 250),
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
        ChunkedBlock(0x0b1b0, 16, 56, 128),
        ChunkedBlock(0x0cdc0, 16, 56, 128),
        ChunkedBlock(0x0e9d0, 16, 56, 128),
        ChunkedBlock(0x105e0, 16, 56, 128),

        # these don't seem to be initialized, what is the limit?
        # ChunkedBlock(0x121f0, 16, 56, 128),
        # ChunkedBlock(0x13e00, 16, 56, 128),
        # ChunkedBlock(0x15a10, 16, 56, 128),
    ]

    CPPart = namedtuple('CPPart',
                        ['mode', 'file_addr', 'radio_addr', 'size'])
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

    @classmethod
    def dump_parts(cls):
        def block_in_part(block, part):
            # start = Codeplug.radio2file(block.raw_offset)
            start = block.raw_offset
            end = start + block.size
            part_end = part.file_addr + part.size
            return (start >= part.file_addr and end < part_end)

        log.debug("-----------  CODEPLUG FILE PARTS  ------------")
        log.debug(" N where t      start - end        size")
        log.debug("----------------------------------------------")
        for i, p in enumerate(cls.parts):
            blocks = [bn for bn, b in cls.blocks.items() if block_in_part(b, p)]
            start = p.file_addr
            end = start + p.size
            mode = 'E' if p.mode == MemType.EEPROM else 'f'
            log.debug(f"{i: 2} file  {mode} 0x{start:08x} - 0x{end:08x} 0x{p.size:06x}  {','.join(blocks)}")
            if p.file_addr == p.radio_addr:
                continue
            start = p.radio_addr
            end = start + p.size
            log.debug(f"{i: 2} radio {mode} 0x{start:08x} - 0x{end:08x} 0x{p.size:06x}  {','.join(blocks)}")


    @classmethod
    def radio2file(cls, addr):
        """Translate address from radio space to file space"""
        for p in cls.parts:
            if addr >= p.radio_addr and addr < p.radio_addr + p.size:
                offset = p.radio_addr - p.file_addr
                return addr - offset
        else:
            return addr

    def __init__(self):
        self.data = bytearray(repeat(0xff, self.SIZE))
        # self.data[0x00:8] = bytearray([0x4d, 0x44, 0x2d, 0x37, 0x36, 0x30, 0x50, 0xff]) # MD-760P
        # self.data[0x80:8] = bytearray([0x00, 0x04, 0x70, 0x04, 0x36, 0x01, 0x74, 0x01]) # freqs
        # self.data[0x90:5] = bytearray([0x47, 0x44, 0x2d, 0x37, 0x37]) # GD-77
        # self.data[0xd8:8] = bytearray([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]) # ???

    def contacts(self):
        for i, chunk in enumerate(self.blocks['contacts'].walk(self.data)):
            if chunk[0] == 0xff:
                continue
            c = Contact.from_buffer(chunk)
            c.index = i
            # if c.used:
            yield c

    def talk_groups(self):
        tgb = self.blocks['tglist']
        table = self.data[tgb.raw_offset : tgb.raw_offset + tgb.item_count]
        for i, c in enumerate(table):
            if c == 0:
                continue

            start = tgb.offset + i * tgb.item_size
            end = start + tgb.item_size
            chunk = self.data[start:end]
            tg = TGList.from_buffer(chunk)
            if not len(tg.name):
                continue
            tg.index = i
            yield tg

    def _channel_block(self, chb):
        table = self.data[chb.raw_offset : chb.offset]
        log.debug(f"walking channels at 0x{chb.offset:08x}, {table}")
        for i, chunk in enumerate(chb.walk(self.data)):
            if (table[i // 8] >> (i % 8)) & 0x01 == 0x00:
                continue
            ch = Channel.from_buffer(chunk)
            ch.index = i
            if not len(ch.name) or ch.mode >= 2:
                continue
            log.debug(f"{i} {chunk}")
            yield ch

    def channels(self):
        for i, chb in enumerate(self.channel_blocks):
            log.debug(f"CHANNEL BANK {i}")
            for ch in self._channel_block(chb):
                ch.index += i*128
                yield ch

    def __bytes__(self):
        return bytes(self.data)

    def __str__(self):
        return str(self.data)

    def __len__(self):
        if not self.data: return 0
        return len(self.data)
