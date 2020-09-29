from unittest import TestCase

from opengd77.codeplug import Codeplug

class CodeplugTestCase(TestCase):

    def test_dmrid_write_read(self):
        cp = Codeplug()

        cp.dmr_id = 123
        self.assertEqual(cp.dmr_id, 123)

        cp.dmr_id = 12345678
        self.assertEqual(cp.dmr_id, 12345678)

        with self.assertRaises(ValueError):
            cp.dmr_id = 123456789

        with self.assertRaises(ValueError):
            cp.dmr_id = -123

    def test_callsign_write_read(self):
        cp = Codeplug()

        cp.callsign = b'abcd'
        self.assertEqual(cp.callsign, 'abcd')

        cp.callsign = 'asdf'
        self.assertEqual(cp.callsign, 'asdf')

        with self.assertRaises(ValueError):
            cp.callsign = 'asdfasdf0'
