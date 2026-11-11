"""Deterministic SYNTHETIC sample content for the hosted seed assets. Nothing here is real source code.

``source_sample`` is source-shaped text with enough variety for content-defined chunking to find cut points.
The interface builds the same bytes in ``frontend/src/api.ts`` (fixture "source"); a test on each side pins
the SHA-256 below, so the two generators cannot drift apart.
"""
SOURCE_SAMPLE_SHA256 = "80d5bd83e3aedc3f3c183f950d7e8233b13c511bb0e1202080cde6747713939e"
SOURCE_SAMPLE_STEPS = 56


def _xorshift32(state: int) -> int:
    state ^= (state << 13) & 0xFFFFFFFF
    state ^= state >> 17
    state ^= (state << 5) & 0xFFFFFFFF
    return state


def source_sample() -> bytes:
    lines = ["# SYNTHETIC RootSentinel demo source sample: pricing/quote_engine.py\n",
             "# Generated deterministically. Not real intellectual property.\n"]
    state = 0x52535344
    for step in range(SOURCE_SAMPLE_STEPS):
        words = []
        for _ in range(4):
            state = _xorshift32(state)
            words.append(f"{state:08x}")
        lines.append(f"\ndef quote_engine_step_{step}(value):\n    # synthetic rule {words[0]}\n"
                     f"    return (value * 0x{words[1]} + 0x{words[2]}) % 0x{words[3]}\n")
    return "".join(lines).encode("ascii")


def protected_sample() -> bytes:
    """The first seed. Repetitive on purpose: it has one content-defined chunk (see docs/detection-spec.md)."""
    return b"SYNTHETIC-PROTECTED-" * 128
