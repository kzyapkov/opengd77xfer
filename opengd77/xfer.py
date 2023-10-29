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

from opengd77.codeplug import Codeplug, MemType, register_yaml
from opengd77.comm import OpenGD77Radio


log = logging.getLogger(__name__)


def get_parsers():
    p = argparse.ArgumentParser()

    # TODO: use usb to find the correct serial port or list matching
    # ports by VID:PID, like dmrconfig does
    p.add_argument('--port', '-p', help="Serial port of radio",
                   default=('COM13' if platform.system() == 'Windows'
                            else '/dev/ttyACM0'))

    p.add_argument('-v', '--verbose', default=False, action='store_true')

    sp = p.add_subparsers(dest='cmd')

    p_read_codeplug = sp.add_parser('read', help="Read codeplug from radio")
    p_read_codeplug.add_argument(
            'file', type=argparse.FileType('wb'),
            help="Where to store codeplug from radio",
            default="codeplug.g77")
    p_read_codeplug.add_argument('--format', help="Output format",
            choices=('bin', 'yaml'), default='bin')

    p_write_codeplug = sp.add_parser('write', help="Write codeplug to radio")
    p_write_codeplug.add_argument(
            'file', type=argparse.FileType('rb'),
            help="Codeplug file to load into radio",
            default="codeplug.g77")

    p_export = sp.add_parser('export', help="Export YAML codeplug from binary or radio")
    p_export.add_argument('input_file', help="Binary codeplug file", nargs='?',
                          type=argparse.FileType('rb'))
    p_export.add_argument('output_file', help="YAML output file",
                          type=argparse.FileType('wb'))

    p_import = sp.add_parser('import', help="Import YAML into radio or overlay over binary")
    p_import.add_argument('output_file', help="Binary codeplug",
                          type=argparse.FileType('wb'))
    p_import.add_argument('input_file', help="YAML file to apply",
                          type=argparse.FileType('rb'))

    p_backup_calib = sp.add_parser('backup_calib', help="Backup calibration data")
    p_backup_calib.add_argument('file', help="Where to store calibration data",
                                type=argparse.FileType('wb'))

    p_restore_calib = sp.add_parser('restore_calib', help="Restore calibration data")
    p_restore_calib.add_argument('file', help="Where to get calibration from",
                                 type=argparse.FileType('rb'))

    p_backup_eeprom = sp.add_parser('backup_eeprom', help="Backup EEPROM data")
    p_backup_eeprom.add_argument('file', help="Where to store EEPROM data",
                                 type=argparse.FileType('wb'))

    p_restore_eeprom = sp.add_parser('restore_eeprom', help="Restore EEPROM data")
    p_restore_eeprom.add_argument('file', help="Where to get EEPROM from",
                                  type=argparse.FileType('rb'))

    p_dump_codeplug = sp.add_parser('dump', help="Debug helper!")
    p_dump_codeplug.add_argument('file', help="File to read from", nargs="?",
                                 type=argparse.FileType('rb'))

    return p, sp


def read_from_radio(port: str) -> Codeplug:
    radio = OpenGD77Radio(port)
    cp = radio.read_codeplug()
    log.info(f"Read {len(cp.data)} bytes")
    return cp


def write_yaml(cp: Codeplug, f) -> None:
    yaml = YAML()
    yaml.default_flow_style = None
    yaml.indent(None, 4, 2)
    register_yaml(yaml)

    dd = cp.as_dict()
    yaml.dump(dd, f)


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
        cp = read_from_radio(args.port)
        if args.format == 'bin':
            args.file.write(cp.data)
        else:
            write_yaml(cp, args.file)

        log.info(f"Read codeplug from {args.port} into {args.file.name}")

    elif args.cmd == 'write':
        log.info(f"Writing codeplug from {args.file.name} into {args.port}")
        cp = Codeplug.from_file(args.file)
        radio = OpenGD77Radio(args.port)
        radio.write_codeplug(cp)
        log.info(f"Wrote {args.file.name} into {args.port}")

    elif args.cmd == 'export':
        log.warning(f"export {args}")
        if args.input_file:
            src = args.input_file
            cp = Codeplug.from_file(args.input_file)
        else:
            src = args.port
            cp = read_from_radio(args.port)

        write_yaml(cp, args.output_file)
        log.info(f"Exported data from {src} into {args.output_file.name}")

    elif args.cmd == 'import':
        # TODO: finish export logic
        cp = Codeplug.from_file(args.output_file)
        yaml = YAML()
        with open(args.input_file, 'rb') as f:
            yml = yaml.load(f.read())

    elif args.cmd == 'backup_calib':
        log.info(f"Storing calibration from {args.port} to {args.file.name}")
        if not args.file.name.endswith('.g77calib'):
            log.info("We strongly recommend to use .g77calib extension")
        radio = OpenGD77Radio(args.port)
        data = radio.read_calibration()
        args.file.write(data)


    elif args.cmd == 'backup_eeprom':
        log.info(f"Storing EEPROM from {args.port} to {args.file.name}")
        if not args.file.name.endswith('.g77eeprom'):
            log.info("We strongly recommend to use .g77eeprom extension")
        radio = OpenGD77Radio(args.port)
        data = radio.read_eeprom()
        args.file.write(data)

    # elif args.cmd == 'restore_calib':
    # elif args.cmd == 'restore_eeprom':

    elif args.cmd == 'dump':

        Codeplug.dump_parts()

        if args.file:
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
                if i: log.info(f"{i.index}\t{i}")
                else: log.info(f"empty")

        dump_seq(cp.contacts, "Contacts")
        dump_seq(cp.talk_groups, "Talk Groups")
        dump_seq(cp.channels, "Channels")

        log.info(f"zone bits: 0x{cp.zones.zbytes.hex()}")
        log.info(f"ch_per_zone: {cp.zones.ch_per_zone}")
        log.debug("zone locations:")
        for i in range(len(cp.zones)):
            addr = cp.zones._find_addr_by_index(i)
            if not addr:
                log.warning(f"{i} not found?!")
                break
            log.debug(f"{i: 6d} 0x{addr:06x}")

        dump_seq(cp.zones, f"Zones: {len(cp.zones)}")

        log.info(f"DMR ID: {cp.dmr_id}")
        log.info(f"  CALL: {cp.callsign}")


if __name__ == '__main__':
    main()
