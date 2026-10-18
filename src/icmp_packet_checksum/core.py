"""ICMP echo packet checksum and construction.

The internet checksum (RFC 1071) is a 16-bit ones-complement sum over
the packet bytes. We use Python's arbitrary-precision integers instead
of C-style unsigned 16-bit registers; the carries are folded back until
the total fits in 16 bits, then the complement is returned. This is the
standard algorithm, just expressed in a language without fixed-width
integers.

Scope decision (stated plainly): This module handles only ICMP echo
request (type 8) and echo reply (type 0) packets. Other ICMP types have
different fields after the first four bytes and would need different
construction logic; supporting them here would mean guessing at layouts
the brief did not ask for.
"""

import struct
from enum import IntEnum
from typing import NamedTuple


class IcmpType(IntEnum):
    """The two ICMP types this library constructs."""

    ECHO_REPLY = 0
    ECHO_REQUEST = 8


class ChecksumError(ValueError):
    """Raised when a parsed packet's checksum does not match its bytes."""


class IcmpEchoPacket(NamedTuple):
    """A fully constructed ICMP echo packet.

    Attributes:
        type: ICMP type code (0 for reply, 8 for request).
        code: ICMP code; always 0 for echo request/reply.
        identifier: 16-bit identifier, set by the sender.
        sequence: 16-bit sequence number, set by the sender.
        payload: Arbitrary payload bytes carried after the header.
        checksum: The 16-bit internet checksum over type+code+id+seq+payload.
    """

    type: int
    code: int
    identifier: int
    sequence: int
    payload: bytes
    checksum: int

    def to_bytes(self) -> bytes:
        """Serialize the packet to wire format.

        The header is ``!BBHHH``: two single bytes (type, code), then three
        big-endian 16-bit fields (checksum, identifier, sequence). The
        checksum is placed second because that is its fixed position on
        the wire; the receiver recomputes the sum with the checksum field
        included, and a correct packet sums to zero.
        """
        return struct.pack(
            "!BBHHH",
            self.type,
            self.code,
            self.checksum,
            self.identifier,
            self.sequence,
        ) + self.payload


def compute_checksum(data: bytes) -> int:
    """Return the 16-bit internet checksum of *data* (RFC 1071).

    The algorithm sums 16-bit big-endian words, folds any carries back
    into the low 16 bits, and returns the bitwise complement. An odd
    number of bytes gets a zero byte appended so the last byte can be
    summed as a full word; this matches the RFC's recommended handling.

    A correct packet, with its checksum field included in *data*, sums
    to zero. Callers building a packet pass the header fields with the
    checksum field set to 0.
    """
    if len(data) % 2 == 1:
        data = data + b"\x00"

    total = 0
    # Struct iteration with a format string is both faster than a Python
    # loop over individual bytes and lets the platform's struct module
    # handle the big-endian word assembly natively.
    words = len(data) // 2
    for value in struct.unpack(f"!{words}H", data):
        total += value

    # Fold 32-bit overflow back into the lower 16 bits. The loop runs at
    # most twice because a 32-bit sum can produce at most one carry.
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def validate(data: bytes) -> bool:
    """Return True if *data* carries a correct ICMP checksum.

    For a valid packet the ones-complement sum of every 16-bit word
    (checksum field included) is zero. We compute the checksum of the
    raw bytes and check for the all-ones result, which is the complement
    of zero.
    """
    if len(data) < 8:
        return False
    return compute_checksum(data) == 0


def build_packet(
    icmp_type: int,
    code: int,
    identifier: int,
    sequence: int,
    payload: bytes = b"",
) -> IcmpEchoPacket:
    """Build an ICMP echo packet with a computed checksum.

    *icmp_type* should be 0 (reply) or 8 (request); *code* is almost
    always 0 for echo packets. The identifier and sequence are 16-bit
    unsigned values; passing a value outside ``[0, 65535]`` raises
    ``struct.error`` via the final pack, which is the clearest signal.
    """
    if icmp_type not in (int(IcmpType.ECHO_REPLY), int(IcmpType.ECHO_REQUEST)):
        raise ValueError(
            f"icmp_type must be {int(IcmpType.ECHO_REQUEST)} (request) "
            f"or {int(IcmpType.ECHO_REPLY)} (reply); got {icmp_type}"
        )
    if code < 0 or code > 0xFF:
        raise ValueError(f"code must be 0..255; got {code}")
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes or bytearray")
    payload = bytes(payload)

    # Per RFC 1071, the checksum field is computed with itself set to zero.
    header = struct.pack("!BBHHH", icmp_type, code, 0, identifier, sequence)
    checksum = compute_checksum(header + payload)

    return IcmpEchoPacket(
        type=icmp_type,
        code=code,
        identifier=identifier,
        sequence=sequence,
        payload=payload,
        checksum=checksum,
    )


def parse_packet(data: bytes) -> IcmpEchoPacket:
    """Parse raw ICMP echo bytes into an :class:`IcmpEchoPacket`.

    Verifies the checksum and raises :class:`ChecksumError` on mismatch.
    Requires at least 8 bytes; anything shorter is not a valid ICMP header.
    """
    if len(data) < 8:
        raise ValueError(f"ICMP packet must be at least 8 bytes; got {len(data)}")
    if not validate(data):
        raise ChecksumError("checksum mismatch: packet is corrupt or truncated")

    # Unpack the header, then slice the rest as payload. We intentionally
    # do not restrict the type/code fields here; if a caller feeds us a
    # non-echo ICMP packet with a valid checksum we return what we see.
    # That is honest parsing — the checksum is the real validation gate.
    icmp_type, code, checksum, identifier, sequence = struct.unpack("!BBHHH", data[:8])
    payload = data[8:]

    return IcmpEchoPacket(
        type=icmp_type,
        code=code,
        identifier=identifier,
        sequence=sequence,
        payload=payload,
        checksum=checksum,
    )
