from unittest import TestCase

from opengd77.binvar import *


class TestBinStruct(BinStruct):
    SIZE = 100

    name = strvar(0, 16)
    surname = strvar(16, 32)

    bcd = bcdvar(48, 4, big_endian=True)
    bcd_le = bcdvar(52, 4, big_endian=False)
    bcd_x10 = bcdvar(56, 4, big_endian=True, multiplier=10)
    bcd_le_x10 = bcdvar(60, 4, big_endian=False, multiplier=10)



class BCDVarTestCase(TestCase):


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



class StrvarTestCase(TestCase):

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



