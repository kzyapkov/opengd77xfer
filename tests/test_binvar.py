from unittest import TestCase, skip

from opengd77.binvar import *


class TestBinStruct(BinStruct):
    SIZE = 100
    FILL = 0xaa

    name = strvar(0, 16)
    surname = strvar(16, 32)

    bcd = bcdvar(48, 4, big_endian=True)
    bcd_le = bcdvar(52, 4, big_endian=False)
    bcd_x10 = bcdvar(56, 4, big_endian=True, multiplier=10)
    bcd_le_x10 = bcdvar(60, 4, big_endian=False, multiplier=10)

    struct = structvar(64, ">h", default=-1)

    structlist = structlist(70, "B", 10, fill=0x00, default=0, filter_=lambda x: x>0)


class BCDVarTest(TestCase):

    def test_writing_bigendian(self):
        val = 123456
        s = TestBinStruct()
        s.bcd = val
        self.assertEqual(s.bcd, val)

    def test_writing_littleendian(self):
        val = 123456
        s = TestBinStruct()
        s.bcd_le = val
        self.assertEqual(s.bcd_le, val)

    def test_bcd_with_multiplier(self):
        val = 123456 * 10
        s = TestBinStruct()
        s.bcd_x10 = val
        self.assertEqual(s.bcd_x10, val)


class StrvarTest(TestCase):

    def test_reading(self):
        ...

    def test_writing_bytes(self):
        s = TestBinStruct()
        s.name = b"bleh"
        self.assertEqual(s.name, "bleh")

    def test_writing_bytearray(self):
        s = TestBinStruct()
        s.name = bytearray(b"bleh")
        self.assertEqual(s.name, "bleh")

    def test_writing_str(self):
        s = TestBinStruct()
        s.surname = "surname is a str"
        self.assertEqual(s.surname, "surname is a str")

    def test_writing_more_than_allowed(self):
        s = TestBinStruct()
        with self.assertRaises(ValueError):
            s.name = "aA" * 10


class StructvarTest(TestCase):

    @skip("defaults do not apply automagically, should they?")
    def test_default_value(self):
        s = TestBinStruct()
        self.assertEqual(s.struct, -1)

    def test_basic_write_read(self):
        s = TestBinStruct()

        s.struct = -12
        self.assertEqual(s.struct, -12)

        s.struct = 123
        self.assertEqual(s.struct, 123)

        s.struct = 32767
        self.assertEqual(s.struct, 32767)

        with self.assertRaises(ValueError):
            s.struct = 32767 + 1


class StructlistTest(TestCase):
    def test_empty_list(self):
        s = TestBinStruct()

        self.assertEqual(s.structlist, [0xaa] * TestBinStruct.structlist._count)

        s.structlist = []
        self.assertEqual(s.structlist, [])
