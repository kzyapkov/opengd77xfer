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
from dataclasses import dataclass
from typing import List

log = logging.getLogger(__name__)


class BinStructMeta(type):
    def __new__(cls, clsname, superclasses, attributedict):
        attributedict['_binvars'] = OrderedDict()
        new_cls = super().__new__(cls, clsname, superclasses, attributedict)
        return new_cls


class BinStruct(metaclass=BinStructMeta):
    """Base class for mapping fields onto chunks of bytes"""

    SIZE = None
    FILL = 0xff

    include_defaults = False

    def __init__(self, data=None, **kwargs):
        if not self.SIZE:
            raise ValueError(f"define SIZE in subclasses")

        if data is None:
            data = bytearray(repeat(self.FILL, self.SIZE))

        if len(data) != self.SIZE:
            raise ValueError(f"need data of len {self.SIZE} got {len(data)}")

        self._data = data

        for k, v in kwargs.items():
            setattr(self, k, v)

    def __iter__(self):
        return self.as_dict().items()

    def items(self):
        return self.as_dict().items()

    def as_dict(self):
        if not self.include_defaults:
            def filterf(k, v): return v.default != getattr(self, k)
        else:
            def filterf(k, v): return True
        d = {k: getattr(self, k) for k, v in self._binvars.items()
             if filterf(k, v)}
        d.update({k: getattr(self, k) for k in self.__dict__
                  if not k.startswith('_')})
        # log.debug(f"keys on {self}: {self.__dict__.keys()}")
        return d

    @classmethod
    def from_dict(cls, d):
        return cls(**d)

    @property
    def data(self):
        if not isinstance(self._data, memoryview):
            return memoryview(self._data)
        return self._data

    @classmethod
    def from_buffer(cls, buf):
        if len(buf) != cls.SIZE:
            raise ValueError(f"need buf of len={cls.SIZE}")
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)
        return cls(buf)

    def __str__(self):
        cls = self.__class__
        if not hasattr(cls, '_binvars'):
            return f"{self.__class__.__name__}(**unknown fields**)"

        fields = [
            f"{name}={getattr(self, name)}" for name in cls._binvars.keys()]
        fields = ", ".join(fields)
        return f"{self.__class__.__name__}({fields})"

    def __repr__(self):
        return f"{self.__class__.__name__}({bytes(self._data)})"


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
        "where the chunked data starts"
        return self.raw_offset + self.preamble

    @property
    def size(self):
        "length of underlying buffer in bytes"
        return self.item_count * self.item_size + self.preamble

    def chunk_slice(self, idx):
        "return a slice which would give chunk from buf"
        idx -= self.index_offset
        assert idx < self.item_count
        addr = self.offset + idx * self.item_size
        return slice(addr, addr + self.item_size)

    def chunk(self, buf, idx):
        "get the chunk of bytes at idx"
        assert len(buf) >= self.raw_offset + self.size
        return buf[self.chunk_slice(idx)]

    def walk(self, buf):
        "iterate over chunks of bytes in this buf"
        for i in range(self.item_count):
            yield self.chunk(buf, i)


class BlockView:
    """Look at a block of memory and see objects and properties

    This uses a `ChunkedBlock` to slice the underlying memory buffer
    and wrap each chunk in `cls`. Uses a `memoryview` of `buf`.
    """

    def __init__(self, buf, cls, /, *chunk_blocks: List[ChunkedBlock]):
        if not isinstance(buf, memoryview):
            buf = memoryview(buf)
        self.buf = buf
        self.cls = cls
        self.chunk_blocks = chunk_blocks

    def _normalize_key(self, key):
        if not isinstance(key, int):
            raise KeyError("only simple indexing is supported")
        if key < 0:
            key = len(self) - key
        return key

    def _find_chunk_block(self, key):
        for cbi in self.chunk_blocks:
            if (key >= cbi.index_offset and
                    key < cbi.index_offset + cbi.item_count):
                return cbi
        else:
            raise KeyError(f"{key} out of range")

    def __getitem__(self, key):
        key = self._normalize_key(key)
        cb = self._find_chunk_block(key)

        i = key - cb.index_offset
        chunk = cb.chunk(self.buf, i)

        obj = self.cls.from_buffer(chunk)
        obj.index = key + cb.index_offset
        return obj

    def __setitem__(self, key, value):
        if not isinstance(value, self.cls):
            raise ValueError(
                f"{self} only stores {self.cls}, {type(value)} given")

        key = self._normalize_key(key)
        cb = self._find_chunk_block(key)
        self.buf[cb.chunk_slice(key)] = value.data

    def __delitem__(self, key):
        key = self._normalize_key(key)
        log.warning(f"{self}.__delitem__({key})")
        # clear memory to FILL bytes?
        raise NotImplemented()

    def __len__(self):
        "number of contained objects"
        return sum((b.item_count for b in self.chunk_blocks))

    def as_list(self, only_valid=False):
        def f(x): return True
        if only_valid:
            def f(x): return x.valid
        return [x for x in self if f(x)]

    def __iter__(self):
        for cb in self.chunk_blocks:
            for i in range(cb.item_count):
                item = self[i+cb.index_offset]
                if item is not None:
                    yield item


class basevar:
    """Represent a field inside a BinStruct"""

    def __init__(self, offset, /, default=None):
        self._offset = offset
        self.default = default
        self._name = None
        self._owner_name = None
        self._fullname = "??"

    def __set_name__(self, owner, name):
        if not issubclass(owner, BinStruct):
            raise TypeError(f"{owner} not a BinStruct")
        if name in owner._binvars:
            raise AttributeError(f"two of {name} on {owner}")

        self._owner_name = owner.__name__
        self._name = name
        self._fullname = f"{self._owner_name}.{self._name}"
        owner._binvars[self._name] = self

    def __delete__(self, instance):
        raise AttributeError(f"{self._fullname} is undeletable")

    def __str__(self):
        return (f"<{self._fullname}@0x{self._offset:x}>")


# class propvar(property, basevar):
#     def __set_name__(self, owner, name):
#         if not hasattr(owner, '_binvars'):
#             owner._binvars = OrderedDict()
#         if name in owner._binvars:
#             raise AttributeError(f"two of {name} on {owner}")
#         owner._binvars[name] = self
#         super().__set_name__(owner, name)


class structvar(basevar):
    def __init__(self, offset, fmt, *, default=None):
        super().__init__(offset, default=default)
        self._struct = struct.Struct(fmt)
        self._size = self._struct.size
        self._end = self._offset + self._size

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        chunk = instance.data[self._offset: self._end]
        if len(chunk) != self._size:
            raise ValueError("underlying buf too short?")
        return self._struct.unpack(bytes(chunk))[0]

    def __set__(self, instance, value):
        b = self._struct.pack(value)
        instance.data[self._offset: self._end] = b


class structlist(basevar):
    def __init__(self, offset, fmt, count, *,
                 filter_=None, fill=0xff, sort=True, default=None):
        super().__init__(offset, default=default)
        self._struct = struct.Struct(fmt)
        self._size = self._struct.size
        self._count = count
        self._filter = filter_
        self._fill_byte = fill
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
        l = []
        for i in range(self._count):
            start, end = self._find_start_end(i)
            chunk = d[start: end]
            val = self._struct.unpack(chunk)[0]
            if self._filter and not self._filter(val):
                continue
            l.append(val)
        if self._sort:
            l = sorted(l)
        return l

    def __set__(self, instance, value):
        """setting the whole list? easy. slice or mutate? not so much so"""
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
        if chunk[0] == 0x00 or chunk[0] == 0xff:
            return ""
        try:
            return bytes(chunk).rstrip(b"\xff").rstrip(b"\0").decode('ascii')
        except UnicodeDecodeError as e:
            log.info(f"unable to decode {bytes(chunk)}, ignoring")
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

        chunk = instance.data[self._offset: self._offset + self._size]
        res = 0
        if self._big_endian:
            chunk = reversed(chunk)
        for i, b in enumerate(chunk):
            res += (((b >> 4) & 0x0f) * 10 + (b & 0x0f)) * (100 ** i)
        return res * self._mult

    def __set__(self, instance, value):
        value = int(value)
        raise NotImplemented()
