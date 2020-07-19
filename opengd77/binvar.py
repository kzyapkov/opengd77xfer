import logging
import struct

log = logging.getLogger(__name__)

class BinContainer:

    SIZE = None

    def __init__(self, **kwargs):
        if not self.SIZE:
            raise ValueError(f"define SIZE in subclasses")

        if '_data' in kwargs:
            data = kwargs.pop('_data')
        else:
            data = bytearray(self.SIZE)

        if len(data) != self.SIZE:
            raise ValueError(f"need data of len={self.SIZE}")

        self._data = data

        for k, v in kwargs.items():
            setattr(self, k, v)

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
    def __init__(self, offset):
        self._offset = offset

    def __set_name__(self, owner, name):
        if not hasattr(owner, '_binvars'):
            owner._binvars = {}
        if name in owner._binvars:
            raise AttributeError("two of {name} on {owner}")

        self._owner_name = owner.__name__
        self._name = name
        self._fullname = f"{self._owner_name}.{self._name}"
        owner._binvars[self._name] = self
        # print(f"__set_name__({self}, {owner}, {name})")

    def __delete__(self, instance):
        raise AttributeError(f"{self._fullname} is undeletable")

    def __str__(self):
        return (f"<{self._fullname}@0x{self._offset:x}>")

class structvar(basevar):
    def __init__(self, offset, fmt):
        self._name = None
        self._owner_name = None
        self._fullname = None
        self._offset = offset
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
    def __init__(self, offset, fmt, count, filter=None):
        self._offset = offset
        self._struct = struct.Struct(fmt)
        self._size = self._struct.size
        self._count = count
        self._filter = filter

    def __get__(self, instance, owner=None):
        if instance is None:
            return self

        d = instance.data
        su = self._struct.unpack
        l = (su(d[self._offset + self._size * i :
                  self._offset + self._size * (i + 1)])[0]
             for i in range(self._count))
        if self._filter:
            l = filter(self._filter, l)
        return list(l)

    def __set__(self, instance, value):
        raise NotImplemented()


class strvar(basevar):
    def __init__(self, offset, size):
        self._offset = offset
        self._size = size

    def __get__(self, instance, owner=None):
        if instance is None:
            return self

        chunk = instance.data[self._offset : self._offset + self._size]
        if len(chunk) != self._size:
            raise ValueError("underlying buf too short?")
        return bytes(chunk).strip(b"\0").strip(b"\xff")

    def __set__(self, instance, value):
        raise NotImplemented()


class bcdvar(basevar):
    def __init__(self, offset, size, *, big_endian=False, mult=1):
        self._offset = offset
        self._size = size
        self._big_endian = big_endian

    def __get__(self, instance, owner=None):
        if instance is None:
            return self

        chunk = instance.data[self._offset : self._offset + self._size]
        res = 0
        if self._big_endian:
            chunk = reversed(chunk)
        for i, b in enumerate(chunk):
            res += (((b>>4) & 0x0f) * 10 + (b & 0x0f)) * (100 ** i)
        return res
