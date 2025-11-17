import unittest

import intel_hex_tool as iht


class TestIntelHexTool(unittest.TestCase):
    def test_address_high_low(self):
        high, low = iht.get_address_high_low(int('12345678ABCD', 0x10))
        # 1234 is not included in either output as it's above 32 bits
        self.assertEqual(int('5678', 0x10), high)
        self.assertEqual(int('ABCD', 0x10), low)

    def test_intel_row_loads_dumps(self):
        good_rows = (
            # Wikipedia's example row for checksum calculation
            (':0300300002337A1E', iht.DATA_RECORD, int('0030', 0x10), bytes.fromhex('02337A')),
            # Various rows from the Eboard-20231012.hex firmware within AD5M Control-2.2.3
            (':020000040801F1', iht.EXTENDED_LINEAR_ADDRESS_RECORD, 0, bytes.fromhex('0801')),
            (':08018000C55E0108C55E01081F', iht.DATA_RECORD, int('0180', 0x10), bytes.fromhex('C55E0108C55E0108')),
            (':0400000508015E7D13', iht.START_ADDRESS_RECORD, 0, bytes.fromhex('08015E7D')),
            (':00000001FF', iht.EOF_RECORD, 0, b''),
        )
        for line, record_type, address, data in good_rows:
            with self.subTest(line):
                row = iht.IntelHexRow.loads(line)
                self.assertEqual([], row.warnings)
                self.assertEqual(line, row.dumps())
                self.assertEqual(record_type, row.record_type)
                self.assertEqual(address, row.address)
                self.assertEqual(data, row.data)

    def test_intel_row_warnings(self):
        bad_rows = (
            # Same wiki row as above with a manually changed checksum
            (':0300300002337A1F', 'Bad checksum for: 0300300002337A1F (1E != 1F)'),
            # Extended address value is 32 bit rather than 16
            (':0400000400000801F1', 'Bad extended address record: 0400000400000801F1'),
            (':040000040801F1', 'Bad byte count for: 040000040801F1 (2 != 4)'),
            # Start address is 16 bit rather than 32
            (':020000055E7D13', 'Bad start address record: 020000055E7D13'),
        )
        for line, warning in bad_rows:
            with self.subTest(line):
                row = iht.IntelHexRow.loads(line)
                self.assertIn(warning, row.warnings)

    def test_load(self):
        files = (
            # NB: test.hex includes leading and trailing comments as well as lines without records
            ('intel', 'tests/data_part*.hex', 123, int('08015E7D', 0x10)),
            ('bin', 'tests/data.bin', -1, 0),
        )
        for kind, file, start, offset in files:
            with self.subTest(kind):
                data = iht.read_hex(file)
                self.assertEqual(start, data.start)
                self.assertEqual(offset, data.offset)
                self.assertEqual('DEADBEEF', data.data.hex().upper())
