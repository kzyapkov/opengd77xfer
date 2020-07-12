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



You need to install future if you're running python2:
    debian like: sudo apt-get install python-future
    or: pip install future

You also need python-serial or python3-serial

On windows install pyserial, pillow and cimage (using pip install ...)

"""
import sys
import os
import time
import ntpath
import getopt
import serial
import platform
import argparse
from datetime import datetime

def get_parser():
    p = argparse.ArgumentParser()
    p.add_argument('--port', '-p', help="Serial port of radio",
                   default=('COM13'
                        if platform.system() == 'Windows'
                        else '/dev/ttyACM0'))

    sp = p.add_subparsers(dest='cmd')
    p_read_codeplug = sp.add_parser('read')
    p_read_codeplug.add_argument(
        'file', help="File to write codeplug from radio",
        default="codeplug.g77")

    p_write_codeplug = sp.add_parser('write')
    p_write_codeplug.add_argument(
        'file', help="File to read codeplug and store in radio",
        default="codeplug.g77")

    return p

#from PIL import Image
#from PIL import ImageDraw, ImageColor

class DummySerial:
    # This class "simulates" GD-77 during development
    dummy = bytearray(4)
    in_waiting = 1
    is_open = True
    def write(self,a):
        self.dummy[0:2] = a[0:2]
        if a[0]==ord('R') and a[1] in [1,2]:
            self.dummy[1] = 0
            self.dummy[2] = 1
        return len(a)
    def read(self,n):
        return self.dummy
    def flush(self):
        pass
    def close(self):
        pass

def serialInit(serialDev):
    ser = serial.Serial()
    ser.port = serialDev
    ser.baudrate = 115200
    ser.bytesize = serial.EIGHTBITS
    ser.parity = serial.PARITY_NONE
    ser.stopbits = serial.STOPBITS_ONE
    ser.timeout = 2.0
    #ser.xonxoff = 0
    #ser.rtscts = 0
    ser.write_timeout = 2.0
    try:
        ser.open()
    except serial.SerialException as err:
        print(str(err))
        sys.exit(1)
    return ser

MAX_TRANSFER_SIZE = 32

PROGRAM_VERSION = '0.0.5'

def usage():
    print("GD-77 Data Transfer v" + PROGRAM_VERSION)
    print("Usage:  " + ntpath.basename(sys.argv[0]) + " [OPTION]")
    print("")
    print("    -h, --help                 : Display this help text,")
    print("    -r, --read                 : Read config (codeplug) from radio,")
    print("    -w, --write                : Write config (codeplug) to radio,")
    print("    -d, --device=<device>      : Use the specified device as serial port,")
    print("    -f, --filename=<filename>  : Config (codeplug) file name,")
    print("")

def printProgress(rw,sofar,length):
    print("\r - {0} 0x{1:X} bytes: {2}%".format(rw,length,sofar * 100 // length), end='')

MODE_READ_FLASH  = 1
MODE_READ_EEPROM = 2

R_SIZE = 8

def getMemoryArea(ser,buf,mode,bufStart,radioStart,length):
    snd = bytearray(R_SIZE)
    snd[0] = ord('R')
    snd[1] = mode
    bufPos = bufStart
    radioPos = radioStart
    remaining = length
    while (remaining > 0):
        batch = min(remaining,MAX_TRANSFER_SIZE)
        snd[2] = (radioPos >> 24) & 0xFF
        snd[3] = (radioPos >> 16) & 0xFF
        snd[4] = (radioPos >>  8) & 0xFF
        snd[5] = (radioPos >>  0) & 0xFF
        snd[6] = (batch >> 8) & 0xFF
        snd[7] = (batch >> 0) & 0xFF
        ret = ser.write(snd)
        if (ret != R_SIZE):
            print("ERROR: write() wrote " + str(ret) + " bytes")
            return False
        rcv = ser.read(3)
        if (rcv[0] == ord('R')):
            gotBytes = (rcv[1] << 8) + rcv[2]
            for i in range(0, gotBytes):
                buf[bufPos] = ser.read(1)[0]
                bufPos += 1
            radioPos += gotBytes
            remaining -= gotBytes
            printProgress('reading',radioPos - radioStart,length)
            sys.stdout.flush()
        else:
            print("read stopped (error at " + str(radioPos) + ")")
            return False
    print("")
    return True

PREP_SIZE = 5

def flashPrepareSector(ser,address):
    data_sector = address // 4096
    snd = bytearray(PREP_SIZE)
    snd[0] = ord('W')
    snd[1] = 1
    snd[2] = (data_sector >> 16) & 0xFF
    snd[3] = (data_sector >>  8) & 0xFF
    snd[4] = (data_sector >>  0) & 0xFF
    ret = ser.write(snd)
    if (ret != PREP_SIZE):
        print("ERROR: write() wrote " + str(ret) + " bytes")
        return False # ???
    rcv = ser.read(2)
    return rcv[0] == snd[0] and rcv[1] == snd[1]

FLASH_SEND_SIZE = 8

def flashSendData(ser,buf,radioStart,length):
    snd = bytearray(FLASH_SEND_SIZE+MAX_TRANSFER_SIZE)
    snd[0] = ord('W')
    snd[1] = 2
    bufPos = 0
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
        snd[FLASH_SEND_SIZE:FLASH_SEND_SIZE+batch] = buf[bufPos:bufPos+batch]
        ret = ser.write(snd)
        if (ret != FLASH_SEND_SIZE+batch):
            print("ERROR: write() wrote " + str(ret) + " bytes")
            return False
        rcv = ser.read(2)
        if not (rcv[0] == snd[0] and rcv[1] == snd[1]):
            print("ERROR: at "+str(radioPos))
        bufPos += batch
        radioPos += batch
        remaining -= batch
    return True

FLASH_WRITE_SIZE = 2

def flashWriteSector(ser):
    snd = bytearray(FLASH_WRITE_SIZE)
    snd[0] = ord('W')
    snd[1] = 3
    ret = ser.write(snd)
    if (ret != FLASH_WRITE_SIZE):
        print("ERROR: write() wrote " + str(ret) + " bytes")
        return False # ???
    rcv = ser.read(2)
    return rcv[0] == snd[0] and rcv[1] == snd[1]

FLASH_BLOCK_SIZE = 4096

def setFlashMemoryArea(ser,buf,bufStart,radioStart,length):
    bufPos = bufStart # index in buf
    radioPos = radioStart # address in radio
    remaining = length
    if (radioPos % FLASH_BLOCK_SIZE != 0):
        print("ERROR: radioPos "+str(radioPos)+" not aligned")
        return False
    if (length == 0):
        return True
    while (remaining > 0):
        batch = min(remaining,FLASH_BLOCK_SIZE)
        flashPrepareSector(ser,radioPos)
        flashSendData(ser,buf[bufPos:bufPos+batch],radioPos,batch)
        flashWriteSector(ser)
        bufPos += batch
        radioPos += batch
        remaining -= batch
        printProgress('flashing',radioPos - radioStart,length)
    print("")
    return True

EEPROM_SEND_SIZE = 8

def eepromSendData(ser,buf,bufStart,radioStart,length):
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
        ret = ser.write(snd)
        if (ret != EEPROM_SEND_SIZE+batch):
            print("ERROR: write() wrote " + str(ret) + " bytes")
            return False
        rcv = ser.read(2)
        if not (rcv[0] == snd[0] and rcv[1] == snd[1]):
            print("ERROR: at "+str(radioPos))
        bufPos += batch
        radioPos += batch
        remaining -= batch
        printProgress('eepromming',radioPos - radioStart,length)
    print("")
    return True

def sendCommand(ser,commandNumber, x_or_command_option_number, y, iSize, alignment, isInverted, message):
    # snd allocation? len 64 or 32? or 23?
    snd = bytearray(7+16)
    snd[0] = ord('C')
    snd[1] = commandNumber
    snd[2] = x_or_command_option_number
    snd[3] = y
    snd[4] = iSize
    snd[5] = alignment
    snd[6] = isInverted
    # copy message to snd[7] (max 16 bytes)
    i = 7
    for c in message:
        if (i > 7+16-1):
            break
        snd[i] = ord(c)
        i += 1
    ser.flush()
    ret = ser.write(snd)
    if (ret != 7+16): # length?
        print("ERROR: write() wrote " + str(ret) + " bytes")
        return False
    rcv = ser.read(3)
    return len(rcv) > 2 and rcv[1] == snd[1]


def cmdShowCPSScreen(ser):
    sendCommand(ser,0, 0, 0, 0, 0, 0, "")

def cmdClearScreen(ser):
    sendCommand(ser,1, 0, 0, 0, 0, 0, "")

def cmdDisplay(ser,x_or_command_option_number, y, iSize, alignment, isInverted, message):
    sendCommand(ser,2, x_or_command_option_number, y, iSize, alignment, isInverted, message)

def cmdRenderCPS(ser):
    sendCommand(ser,3, 0, 0, 0, 0, 0, "")

def cmdCloseCPSScreen(ser):
    sendCommand(ser,5, 0, 0, 0, 0, 0, "")

OPT_SAVE_SETTINGS_NOT_VFOS = 0
OPT_REBOOT                 = 1
OPT_SAVE_SETTINGS_AND_VFOS = 2
OPT_FLASH_GREEN_LED        = 3
OPT_FLASH_RED_LED          = 4

def cmdCommand(ser,option_number):
    sendCommand(ser,6, option_number, 0, 0, 0, 0, "")

CODEPLUG_SIZE = 0x20000

def initEmptyCodeplug(buf):
    # CPS checks first 8 bytes. This gap is not read/written to radio.
    # fill the entire codeplug with 0xFF
    for i in range(0,CODEPLUG_SIZE):
        buf[i] = 0xFF
    buf[0x00:8] = bytearray([0x4d,0x44,0x2d,0x37,0x36,0x30,0x50,0xff]) # MD-760P
    buf[0x80:8] = bytearray([0x00,0x04,0x70,0x04,0x36,0x01,0x74,0x01]) # freqs
    buf[0x90:5] = bytearray([0x47,0x44,0x2d,0x37,0x37]) # GD-77
    buf[0xd8:8] = bytearray([0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]) # ???

def getConfig(ser,filename):
    buf = bytearray(CODEPLUG_SIZE)
    cmdShowCPSScreen(ser)
    cmdClearScreen(ser)
    cmdDisplay(ser,0, 0,3,1,0,"CPS")
    cmdDisplay(ser,0,16,3,1,0,"Reading")
    cmdDisplay(ser,0,32,3,1,0,"Codeplug")
    cmdRenderCPS(ser)
    cmdCommand(ser,OPT_FLASH_GREEN_LED)
    cmdCommand(ser,OPT_SAVE_SETTINGS_AND_VFOS)
    initEmptyCodeplug(buf)
    getMemoryArea(ser,buf,MODE_READ_EEPROM, 0x00E0, 0x00E0, 0x5f20)
    getMemoryArea(ser,buf,MODE_READ_EEPROM, 0x7500, 0x7500, 0x3B00)
    getMemoryArea(ser,buf,MODE_READ_FLASH,  0xB000,0x7b000,0x13E60)
    getMemoryArea(ser,buf,MODE_READ_FLASH, 0x1EE60,0x00000, 0x11A0)
    cmdCloseCPSScreen(ser)
    with open(filename,'wb') as f:
        f.write(buf)

def setConfig(ser,filename):
    with open(filename,'rb') as f:
        buf = bytearray(f.read())
    cmdShowCPSScreen(ser)
    cmdClearScreen(ser)
    cmdDisplay(ser,0, 0,3,1,0,"CPS")
    cmdDisplay(ser,0,16,3,1,0,"Writing")
    cmdDisplay(ser,0,32,3,1,0,"Codeplug")
    cmdRenderCPS(ser)
    cmdCommand(ser,OPT_FLASH_RED_LED)
    cmdCommand(ser,OPT_SAVE_SETTINGS_AND_VFOS)
    eepromSendData(ser,buf, 0x00E0, 0x00E0, 0x5f20)
    eepromSendData(ser,buf, 0x7500, 0x7500, 0x3B00)
    setFlashMemoryArea(ser,buf,  0xB000,0x7b000,0x13E60)
    setFlashMemoryArea(ser,buf, 0x1EE60,0x00000, 0x11A0)
    # cmdCloseCPSScreen(ser)
    cmdCommand(ser,OPT_SAVE_SETTINGS_NOT_VFOS)

def main():
    # Default tty
    parser = get_parser()
    args = parser.parse_args()

    ser = serialInit(args.port)
    if args.cmd == 'read':
        if not args.file.endswith('.g77'):
            args.file = f"{args.file}.g77"
        print(f"Reading codeplug from {args.port} into {args.file}")
        getConfig(ser, args.file)

    if args.cmd == 'write':
        if not args.file.endswith('.g77'):
            args.file = f"{args.file}.g77"
        print(f"Writing codeplug from {args.file} into {args.port}")
        setConfig(ser, args.file)

    if (ser.is_open):
        ser.close()


if __name__ == '__main__':
    main()
