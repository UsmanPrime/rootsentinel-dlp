"""Content-defined chunking for the detection profile rs-cdc-gear-v1.

FastCDC with normalized chunking (Xia et al., USENIX ATC 2016, Algorithm 1; IEEE TPDS 2020, Algorithm 2),
with the parameters of this profile. The whole definition is in docs/cryptographic-spec.md and
docs/detection-spec.md. This module is separate from rs-fixed-sha256-v1 and changes nothing in it.

A chunk identifier is the SHA-256 of the chunk bytes. Chunk boundaries are similarity evidence only:
they are not a commitment, carry no ordering proof and are not covered by a Merkle root.
"""
from dataclasses import dataclass
from hashlib import sha256

from .models import MAX_FILE_SIZE, digest_bytes, integer

CDC_PROFILE_ID = "rs-cdc-gear-v1"
CDC_PROFILE_VERSION = 1
MIN_SIZE = 512
NORMAL_SIZE = 2048
MAX_SIZE = 8192
NORMALIZATION_LEVEL = 2
# The 13-bit mask of the paper (MaskA of Algorithm 2). Used before NORMAL_SIZE: 11 + 2 effective bits.
MASK_S = 0x0000D93003530000
# The paper's 11-bit MaskL with its two lowest set bits (16 and 17) cleared. Used from NORMAL_SIZE: 11 - 2 bits.
MASK_L = 0x0000D90003500000
GEAR_DOMAIN = b"RootSentinel rs-cdc-gear-v1 gear table"
_WORD = 0xFFFFFFFFFFFFFFFF


def gear_table() -> tuple[int, ...]:
    """256 64-bit values: SHA-256(GEAR_DOMAIN || u32be(counter)) for counter 0..63, each digest read as four
    big-endian 64-bit integers. Gear[4 * counter + k] is bytes 8k..8k+7 of digest number counter."""
    values = []
    for counter in range(64):
        block = sha256(GEAR_DOMAIN + counter.to_bytes(4, "big")).digest()
        values.extend(int.from_bytes(block[k:k + 8], "big") for k in range(0, 32, 8))
    return tuple(values)


GEAR = gear_table()


def gear_table_sha256() -> str:
    """SHA-256 over the 2,048 bytes of the table (256 big-endian 64-bit values in index order)."""
    return sha256(b"".join(value.to_bytes(8, "big") for value in GEAR)).hexdigest()


@dataclass(frozen=True, slots=True)
class CdcChunk:
    offset: int
    length: int
    sha256: str

    def __post_init__(self) -> None:
        integer(self.offset, 0, MAX_FILE_SIZE - 1, "chunk offset")
        integer(self.length, 1, MAX_SIZE, "chunk length")
        digest_bytes(self.sha256)

    def to_dict(self) -> dict:
        return {"offset": self.offset, "length": self.length, "sha256": self.sha256}


def cut_points(data) -> list[int]:
    """End offsets of the chunks of ``data`` in order; the last one is len(data). Empty input has no chunk.

    Per chunk starting at ``start`` with ``n`` bytes left (Algorithm 2 of the 2020 paper):
    n <= MIN_SIZE is one final chunk. Otherwise the hash starts at 0 and takes the bytes from
    start + MIN_SIZE on: fp = ((fp << 1) + Gear[byte]) mod 2^64. The chunk ends BEFORE the first byte at
    relative position i whose update leaves fp & mask == 0, with MASK_S for i < NORMAL_SIZE and MASK_L after,
    and at MAX_SIZE or the end of the input when no position qualifies.
    """
    view = memoryview(data)
    total = len(view)
    gear, mask_s, mask_l, word = GEAR, MASK_S, MASK_L, _WORD
    minimum, normal_size, maximum = MIN_SIZE, NORMAL_SIZE, MAX_SIZE
    cuts = []
    start = 0
    while total - start > minimum:
        end = start + maximum
        if end > total:
            end = total
        normal = start + normal_size
        if normal > end:
            normal = end
        position = start + minimum
        fp = 0
        cut = -1
        for byte in view[position:normal]:
            fp = (fp << 1) + gear[byte] & word
            if not fp & mask_s:
                cut = position
                break
            position += 1
        else:
            for byte in view[normal:end]:
                fp = (fp << 1) + gear[byte] & word
                if not fp & mask_l:
                    cut = position
                    break
                position += 1
        start = end if cut < 0 else cut
        cuts.append(start)
    if start < total:
        cuts.append(total)
    return cuts


def cdc_chunks(data: bytes) -> tuple[CdcChunk, ...]:
    if type(data) is not bytes:
        raise ValueError("Input must be bytes")
    if len(data) > MAX_FILE_SIZE:
        raise ValueError("File exceeds 10 MiB limit")
    view = memoryview(data)
    chunks, start = [], 0
    for end in cut_points(data):
        chunks.append(CdcChunk(start, end - start, sha256(view[start:end]).hexdigest()))
        start = end
    return tuple(chunks)
