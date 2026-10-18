import struct
import unittest

from icmp_packet_checksum import (
    IcmpEchoPacket,
    IcmpType,
    compute_checksum,
    validate,
    build_packet,
    parse_packet,
    ChecksumError,
)


class TestComputeChecksum(unittest.TestCase):
    def test_empty_input_returns_ones(self):
        # The complement of zero is 0xFFFF. An empty sum is zero.
        self.assertEqual(compute_checksum(b""), 0xFFFF)

    def test_all_zero_bytes_returns_ones(self):
        self.assertEqual(compute_checksum(b"\x00\x00\x00\x00"), 0xFFFF)

    def test_single_odd_byte(self):
        # 0x0100 as a big-endian word, complement of 0x0100 is 0xFEFF.
        self.assertEqual(compute_checksum(b"\x01"), 0xFEFF)

    def test_known_echo_request_no_payload(self):
        # Manually verified: type=8, code=0, checksum=0, id=1, seq=1.
        # Header words: 0x0800 + 0x0000 + 0x0001 + 0x0001 = 0x0802
        # Complement of 0x0802 = 0xF7FD.
        header = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
        self.assertEqual(compute_checksum(header), 0xF7FD)

    def test_checksum_property_sums_to_zero(self):
        # The defining property: a correct packet with its checksum field
        # included must sum to zero, so compute_checksum returns 0x0000.
        pkt = build_packet(8, 0, 0x1234, 1, b"hello")
        self.assertEqual(compute_checksum(pkt.to_bytes()), 0x0000)

    def test_odd_length_padded_with_zero(self):
        # 0x0100 (from \x01\x00) + 0xFF00 (from \xFF + padded \x00) = 0x10000
        # -> fold -> 0x0001 -> complement -> 0xFFFE.
        self.assertEqual(compute_checksum(b"\x01\x00\xFF"), 0xFFFE)

    def test_carry_folding_with_large_sum(self):
        # Many 0xFFFF words force multiple carries; ensure they fold.
        # Each 0xFFFF word. 65535 * 2 = 131070 -> fold: 0x0001 + 0xFFFE = 0xFFFF
        # -> complement = 0x0000.
        self.assertEqual(compute_checksum(b"\xFF\xFF\xFF\xFF"), 0x0000)


class TestBuildPacket(unittest.TestCase):
    def test_request_no_payload(self):
        pkt = build_packet(8, 0, 1, 1, b"")
        self.assertEqual(pkt.type, 8)
        self.assertEqual(pkt.code, 0)
        self.assertEqual(pkt.identifier, 1)
        self.assertEqual(pkt.sequence, 1)
        self.assertEqual(pkt.payload, b"")
        self.assertEqual(pkt.checksum, 0xF7FD)

    def test_reply_with_payload(self):
        payload = b"ping-data"
        pkt = build_packet(0, 0, 0xABCD, 0x0001, payload)
        self.assertEqual(pkt.type, 0)
        self.assertEqual(pkt.payload, payload)
        self.assertTrue(validate(pkt.to_bytes()))

    def test_default_payload_is_empty(self):
        pkt = build_packet(8, 0, 1, 1)
        self.assertEqual(pkt.payload, b"")

    def test_to_bytes_round_trips_through_parse(self):
        original = build_packet(8, 0, 0xBEEF, 42, b"payload bytes")
        raw = original.to_bytes()
        parsed = parse_packet(raw)
        self.assertEqual(parsed, original)

    def test_invalid_type_raises(self):
        with self.assertRaises(ValueError):
            build_packet(13, 0, 1, 1, b"")

    def test_invalid_code_raises(self):
        with self.assertRaises(ValueError):
            build_packet(8, 256, 1, 1, b"")

    def test_negative_code_raises(self):
        with self.assertRaises(ValueError):
            build_packet(8, -1, 1, 1, b"")

    def test_non_bytes_payload_raises(self):
        with self.assertRaises(TypeError):
            build_packet(8, 0, 1, 1, "not bytes")  # type: ignore[arg-type]

    def test_bytearray_payload_accepted(self):
        pkt = build_packet(8, 0, 1, 1, bytearray(b"abc"))
        self.assertEqual(pkt.payload, b"abc")


class TestValidate(unittest.TestCase):
    def test_valid_packet(self):
        pkt = build_packet(8, 0, 1, 1, b"data")
        self.assertTrue(validate(pkt.to_bytes()))

    def test_corrupted_packet(self):
        pkt = build_packet(8, 0, 1, 1, b"data")
        raw = bytearray(pkt.to_bytes())
        raw[7] ^= 0x01  # flip a bit in the sequence field
        self.assertFalse(validate(bytes(raw)))

    def test_too_short(self):
        self.assertFalse(validate(b"\x08\x00"))


class TestParsePacket(unittest.TestCase):
    def test_parses_valid_packet(self):
        built = build_packet(0, 0, 0x1234, 0x5678, b"hello")
        parsed = parse_packet(built.to_bytes())
        self.assertEqual(parsed.type, 0)
        self.assertEqual(parsed.code, 0)
        self.assertEqual(parsed.identifier, 0x1234)
        self.assertEqual(parsed.sequence, 0x5678)
        self.assertEqual(parsed.payload, b"hello")
        self.assertEqual(parsed.checksum, built.checksum)

    def test_corrupt_raises_checksum_error(self):
        built = build_packet(8, 0, 1, 1, b"hi")
        raw = bytearray(built.to_bytes())
        raw[4] ^= 0xFF
        with self.assertRaises(ChecksumError):
            parse_packet(bytes(raw))

    def test_short_raises_value_error(self):
        with self.assertRaises(ValueError):
            parse_packet(b"\x08\x00\x00")

    def test_preserves_odd_length_payload(self):
        built = build_packet(8, 0, 1, 1, b"abc")
        parsed = parse_packet(built.to_bytes())
        self.assertEqual(parsed.payload, b"abc")
        # Odd-length payload is padded during checksum computation but
        # the stored payload must be the original bytes, not the padded.
        self.assertEqual(len(parsed.payload), 3)


class TestIcmpType(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(int(IcmpType.ECHO_REQUEST), 8)
        self.assertEqual(int(IcmpType.ECHO_REPLY), 0)


class TestNamedTupleSerialization(unittest.TestCase):
    def test_to_bytes_matches_struct_pack(self):
        pkt = IcmpEchoPacket(
            type=8, code=0, identifier=1, sequence=1, payload=b"", checksum=0xF7FD
        )
        expected = struct.pack("!BBHHH", 8, 0, 0xF7FD, 1, 1)
        self.assertEqual(pkt.to_bytes(), expected)


if __name__ == "__main__":
    unittest.main()
