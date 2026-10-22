# icmp-packet-checksum

Computes and validates the 16-bit internet checksum (RFC 1071) for ICMP echo request and reply packets, constructing the full packet with type, code, identifier, and sequence fields.

```python
from icmp_packet_checksum import build_packet, parse_packet, validate

# Build an echo request with a payload.
pkt = build_packet(
    icmp_type=8,
    code=0,
    identifier=0x1234,
    sequence=1,
    payload=b"hello",
)
raw = pkt.to_bytes()
print(pkt.checksum)  # 0x...  the computed 16-bit checksum

# Validate raw bytes and parse them back.
assert validate(raw)
parsed = parse_packet(raw)
assert parsed.identifier == 0x1234
assert parsed.payload == b"hello"
```

## Why this exists

When constructing ICMP echo packets by hand (for raw socket probes, connectivity checks, or test harnesses), the checksum is the one field that must be computed, not hardcoded. Getting it wrong means the kernel or the remote stack silently drops the packet. This library does exactly that computation and nothing else — no socket wrapping, no send/receive, no protocol negotiation. The trade-off is narrow scope for zero dependencies and a code path small enough to audit by eye.

## Edge cases

The checksum algorithm sums 16-bit big-endian words. If the packet has an odd number of bytes, the last byte is padded with a zero byte for the sum only — the stored payload is unchanged. This matches RFC 1071's recommendation, but it means `compute_checksum(b"\x01")` returns the checksum of `b"\x01\x00"`, not of a single byte.

The library constructs and parses echo request (type 8) and echo reply (type 0) packets only. Passing another ICMP type to `build_packet` raises `ValueError`. `parse_packet` does not restrict the type field — if a non-echo ICMP packet with a valid checksum is passed in, it returns what it sees, because the checksum is the real validation gate and the field layout for the first eight bytes is shared across ICMP types.

## Exported names

- `IcmpType` — enum with `ECHO_REQUEST` (8) and `ECHO_REPLY` (0).
- `IcmpEchoPacket` — namedtuple with fields `type`, `code`, `identifier`, `sequence`, `payload`, `checksum`, and a `to_bytes()` method.
- `compute_checksum(data: bytes) -> int` — returns the 16-bit checksum of raw bytes.
- `validate(data: bytes) -> bool` — True if the bytes carry a correct checksum.
- `build_packet(icmp_type, code, identifier, sequence, payload=b"") -> IcmpEchoPacket` — builds a packet with a computed checksum.
- `parse_packet(data: bytes) -> IcmpEchoPacket` — parses and validates raw bytes; raises `ChecksumError` on mismatch.
- `ChecksumError` — raised by `parse_packet` when the checksum does not match.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

