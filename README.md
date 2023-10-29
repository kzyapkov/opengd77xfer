# opengd77xfer

[![works badge](https://cdn.jsdelivr.net/gh/nikku/works-on-my-machine@v0.2.0/badge.svg)](https://github.com/nikku/works-on-my-machine)

## Overview

I use Linux and prefer open-source. OpenGD77 is great, but there is no
proper codeplug-editing solution for Linux. This here tries to do that.

Still very raw, key features missing.

## Roadmap

 Notes to self, what needs to be done:

  * implement "import", i.e. modifying a binary from yaml
  * add settings in codeplug (?)

## Installation

    pip install git+https://github.com/kzyapkov/opengd77xfer.git

should work, then

    gd77xfer -h
    gd77xfer <subcommand> -h


## Usage

The tool supports reading and writing in the original binary format:

    gd77xfer -p /dev/myradio read my-codeplug.g77
    gd77xfer -p /dev/myradio write my-codeplug.g77

Reading-writing whole EEPROM:

    gd77xfer -p /dev/myradio backup_eeprom my-eeprom.g77eeprom
    gd77xfer -p /dev/myradio restore_eeprom my-eeprom.g77eeprom

The intention is to support import/export to yaml, but currently only export
is implemented

    gd77xfer export my-codeplug.g77 my-codeplug.yml


## Contribution

    python3.11 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    python opengd77/xfer.py ....


## Copyright

This code was originally published on

http://www.opengd77.com/viewtopic.php?f=12&t=959&p=8847

by user oh1fss, licensed under GPLv2.

    Copyright (C) 2020  OH1FSS, juhani.jaakola@iki.fi
                F1RMB, Daniel Caujolle-Bert <f1rmb.daniel@gmail.com>
                VK3KYY / G4KYF, Roger Clark
                LZ1CK, Kiril Zyapkov
