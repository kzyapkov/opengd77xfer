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
from datetime import datetime

import serial
from ruamel.yaml import YAML

from .codeplug import Channel, Codeplug, Contact, MemType, TGList, Zone
from .comm import OpenGD77Radio


log = logging.getLogger(__name__)
yaml = YAML()

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
    p_read_codeplug.add_argument('--format', help="Output format",
            choices=('bin', 'yaml'), default='yaml')

    p_write_codeplug = sp.add_parser('write', help="Write codeplug to radio")
    p_write_codeplug.add_argument(
            'file', help="Codeplug file to load into radio",
            default="codeplug.g77")

    p_backup_calib = sp.add_parser('backup_calib', help="Backup calibration data")
    p_backup_calib.add_argument('file', help="Where to store calibration data")

    p_restore_calib = sp.add_parser('restore_calib', help="Restore calibration data")
    p_restore_calib.add_argument('file', help="Where to get calibration from")

    p_backup_eeprom = sp.add_parser('backup_eeprom', help="Backup calibration data")
    p_backup_eeprom.add_argument('file', help="Where to store EEPROM data")

    p_restore_eeprom = sp.add_parser('restore_eeprom', help="Restore calibration data")
    p_restore_eeprom.add_argument('file', help="Where to get EEPROM from")

    p_dump_yaml = sp.add_parser('dump_yaml', help="Dump codeplug into a yml file")
    p_dump_yaml.add_argument('file', help="Where to store yml codeplug")

    p_dump_codeplug = sp.add_parser('dump', help="Debug helper!")
    p_dump_codeplug.add_argument('file', help="File to read from", nargs="?")

    return p, sp


def main():

    parser, subparsers = get_parsers()
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        stream=sys.stderr, format="%(asctime)-15s %(filename)s:%(lineno)d %(message)s")

    if args.cmd not in subparsers.choices:
        log.info("No command given.")
        sys.exit(1)

    if args.cmd == 'read': # from radio into file
        log.warning(args)
        if not args.file.endswith('.g77'):
            args.file = f"{args.file}.g77"
        log.info(f"Reading codeplug from {args.port} into {args.file}")
        radio = OpenGD77Radio(args.port)
        cp = radio.read_codeplug()
        log.info(f"Read {len(cp.data)} bytes")

        if args.format == 'bin':
            with open(args.file, 'wb') as f:
                f.write(cp.data)
        elif args.format == 'yaml':
            print(yaml.dump([z.as_dict() for z in cp.zones]))
            print(yaml.dump([z.as_dict() for z in cp.contacts]))
            print(yaml.dump([z.as_dict() for z in cp.channels]))
            print(yaml.dump([z.as_dict() for z in cp.talk_groups]))

    elif args.cmd == 'write':
        log.info(f"Writing codeplug from {args.file} into {args.port}")
        cp = Codeplug.from_file(args.file)
        radio = OpenGD77Radio(args.port)
        radio.write_codeplug(cp)

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

    elif args.cmd == 'dump':

        Codeplug.dump_parts()

        if args.file and os.path.exists(args.file):
            log.info(f"Loading codeplug from {args.file}")
            cp = Codeplug.from_file(args.file)
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

        log.debug(f"zone bits: 0x{cp.zones.zbytes.hex()}")
        log.debug(f"ch_per_zone: {cp.zones.ch_per_zone}")
        log.debug("zone locations:")
        for i in range(len(cp.zones)):
            addr = cp.zones._find_addr_by_index(i)
            log.debug(f"{i: 6d} 0x{addr:06x}")

    elif args.cmd == 'dump_yaml':

        cp = Codeplug.from_file(args.file)

        yaml.default_flow_style = None
        yaml.dump({
            'zones': [z.as_dict() for z in cp.zones],
            'contacts': [z.as_dict() for z in cp.contacts],
            'channels': [z.as_dict() for z in cp.channels],
            'talk_groups': [z.as_dict() for z in cp.talk_groups],
        }, sys.stdout)

    else:
        log.warning(f"not implemented: {args.cmd}")


if __name__ == '__main__':
    main()
