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
from collections import OrderedDict
from itertools import repeat

# from ruamel.yaml import YAML
# yaml = YAML()
# yaml.default_flow_style = None
# yaml.indent(mapping=4, sequence=4, offset=2)


log = logging.getLogger(__name__)

class BinContainer:

    SIZE = None
    FILL = 0xff

    include_defaults = False

    def __init__(self, **kwargs):
        if not self.SIZE:
            raise ValueError(f"define SIZE in subclasses")

        if '_data' in kwargs:
            data = kwargs.pop('_data')
        else:
            data = bytearray(repeat(self.FILL, self.SIZE))

        if len(data) != self.SIZE:
            raise ValueError(f"need data of len={self.SIZE}")

        self._data = data

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __getstate__(self):
        return self.as_dict()

    def __setstate__(self, d):
        for k, v in d.items():
            setattr(self, k, v)

    def __iter__(self):
        return self.as_dict().items()

    def items(self):
        return self.as_dict().items()

    def as_dict(self):
        if not self.include_defaults:
            f = lambda k, v: v.default != getattr(self, k)
        else:
            f = lambda k, v: True
        d = {k: getattr(self, k) for k, v in self._binvars.items()
             if f(k, v)}
        d.update({k: getattr(self, k) for k in self.__dict__
                  if not k.startswith('_')})
        # log.debug(f"keys on {self}: {self.__dict__.keys()}")
        return d

    @classmethod
    def from_dict(cls):
        raise NotImplemented()

    @property
    def data(self):
        if not isinstance(self._data, memoryview):
            return memoryview(self._data)
        return self._data

    @classmethod
    def from_buffer(cls, buf):
        if len(buf) != cls.SIZE:
            raise ValueError(f"need buf of len={cls.SIZE}")
        return cls(_data=buf)

    def __str__(self):
        if not hasattr(self, '_binvars'):
            return f"{self.__class__.__name__}(**unknown fields**)"
        fields = [f"{name}={getattr(self, name)}" for name in self._binvars.keys()]
        fields = ", ".join(fields)
        return f"{self.__class__.__name__}({fields})"

    def fields(self):
        return [f"{name}={getattr(self, name)}" for name in self._binvars.keys()]

    def __repr__(self):
        # list attributes
        return f"{self.__class__.__name__}({bytes(self._data)})"

class basevar:
    def __init__(self, offset, /, default=None):
        self._offset = offset
        self.default = default
        self._name = None
        self._owner_name = None
        self._fullname = "??"

    def __set_name__(self, owner, name):
        if not hasattr(owner, '_binvars'):
            owner._binvars = OrderedDict()
        if name in owner._binvars:
            raise AttributeError("two of {name} on {owner}")

        self._owner_name = owner.__name__
        self._name = name
        self._fullname = f"{self._owner_name}.{self._name}"
        owner._binvars[self._name] = self

    def __delete__(self, instance):
        raise AttributeError(f"{self._fullname} is undeletable")

    def __str__(self):
        return (f"<{self._fullname}@0x{self._offset:x}>")

class structvar(basevar):
    def __init__(self, offset, fmt, *, default=None):
        super().__init__(offset, default=default)
        self._struct = struct.Struct(fmt)
        self._size = self._struct.size
        self._end = self._offset + self._size

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        chunk = instance.data[self._offset : self._end]
        if len(chunk) != self._size:
            raise ValueError("underlying buf too short?")
        return self._struct.unpack(bytes(chunk))[0]

    def __set__(self, instance, value):
        b = self._struct.pack(value)
        instance.data[self._offset : self._end] = b

class structlist(basevar):
    def __init__(self, offset, fmt, count, *, filter=None, fill_byte=0xff, sort=True, default=None):
        super().__init__(offset, default=default)
        self._struct = struct.Struct(fmt)
        self._size = self._struct.size
        self._count = count
        self._filter = filter
        self._fill_byte = fill_byte
        self._sort = sort

    def _find_start_end(self, i):
        return (
            self._offset + self._size * i,
            self._offset + self._size * (i + 1)
        )

    def __get__(self, instance, owner=None):
        if instance is None:
            return self

        d = instance.data
        # su = self._struct.unpack
        # l = (su(d[self._offset + self._size * i :
        #           self._offset + self._size * (i + 1)])[0]
        #      for i in range(self._count))
        # if self._filter:
        #     l = filter(self._filter, l)
        l = []
        for i in range(self._count):
            start, end = self._find_start_end(i)
            chunk = d[start : end]
            val = self._struct.unpack(chunk)[0]
            if self._filter and not self._filter(val):
                continue
            l.append(val)
        if self._sort:
            l = sorted(l)
        return l

    def __set__(self, instance, value):
        """setting the whole list? I may need more magic!!!"""
        raise NotImplemented()


class strvar(basevar):
    def __init__(self, offset, size, default=None):
        super().__init__(offset, default=default)
        self._size = size

    def __get__(self, instance, owner=None):
        if instance is None:
            return self

        chunk = instance.data[self._offset : self._offset + self._size]
        if len(chunk) != self._size:
            raise ValueError("underlying buf too short?")
        try:
            return bytes(chunk).strip(b"\0").strip(b"\xff").decode('ascii')
        except UnicodeDecodeError:
            return ""

    def __set__(self, instance, value):
        if isinstance(value, str):
            value = value.encode('ascii')
        elif not isinstance(value, (bytes, bytearray)):
            raise ValueError()

        chunk = bytearray(value)
        if len(chunk) < self._size:
            pad = self._size - len(chunk)
            chunk.extend(bytearray(repeat(0xff, pad)))

class bcdvar(basevar):
    def __init__(self, offset, size, *, big_endian=False, mult=1, default=None):
        super().__init__(offset, default=default)
        self._size = size
        self._big_endian = big_endian
        self._mult = mult

    def __get__(self, instance, owner=None):
        if instance is None:
            return self

        chunk = instance.data[self._offset : self._offset + self._size]
        res = 0
        if self._big_endian:
            chunk = reversed(chunk)
        for i, b in enumerate(chunk):
            res += (((b>>4) & 0x0f) * 10 + (b & 0x0f)) * (100 ** i)
        return res * self._mult

    def __set__(self, instance, value):
        value = int(value)
        raise NotImplemented()
