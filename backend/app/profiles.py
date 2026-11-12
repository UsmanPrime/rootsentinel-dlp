"""Detection profile registry, in front of detection.py.

A profile has an id, a version, published parameters and three functions: fingerprint the bytes of an
asset version or of an upload, store an asset version's fingerprint, and match an upload fingerprint
against the current versions of the active assets.

rs-fixed-sha256-v1 is registered here unchanged: its fingerprint is ``crypto.fingerprint_bytes``, its
rows are ``asset_chunks`` and its matcher is ``detection.detect``. A new detection method is a new
profile with a new id; an existing profile is never altered in place.
"""
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from sqlalchemy import func, select

from . import detection
from .crypto import CHUNK_SIZE, PROFILE_ID, cdc, fingerprint_bytes
from .crypto.models import SPEC_VERSION
from .errors import Indeterminate
from .models import Asset, AssetCdcChunk, AssetChunk, AssetVersion
from .schemas import DetectionView, ProfileEvidence, ProfileMatch, ProfileView, VersionProfile

FIXED_ID = PROFILE_ID
CDC_ID = cdc.CDC_PROFILE_ID
CDC_LOOKUP_BATCH = 500


@dataclass(frozen=True)
class Profile:
    id: str
    version: int
    summary: str
    parameters: MappingProxyType
    fingerprint: Callable[[bytes], Any]
    store: Callable[[Any, str, Any], None]
    match: Callable[[Any, Any], ProfileEvidence]

    def view(self) -> ProfileView:
        return ProfileView(id=self.id, version=self.version, summary=self.summary, parameters=dict(self.parameters))


_REGISTRY: dict[str, Profile] = {}


def register_profile(profile: Profile) -> Profile:
    if profile.id in _REGISTRY:
        raise ValueError("A registered profile is never replaced; publish a new versioned profile id")
    _REGISTRY[profile.id] = profile
    return profile


def get(profile_id: str) -> Profile:
    profile = _REGISTRY.get(profile_id)
    if profile is None:
        raise Indeterminate("UNSUPPORTED_PROFILE")
    return profile


def registered() -> tuple[Profile, ...]:
    """In registration order: the fixed profile first."""
    return tuple(_REGISTRY.values())


def merged(intervals) -> list[tuple[int, int]]:
    """Sorted half-open intervals as maximal runs. The sum of the run lengths is the size of the union."""
    runs: list[tuple[int, int]] = []
    for begin, end in sorted(intervals):
        if runs and begin <= runs[-1][1]:
            if end > runs[-1][1]:
                runs[-1] = (runs[-1][0], end)
        else:
            runs.append((begin, end))
    return runs


# ---------------------------------------------------------------------------------------------- rs-fixed-sha256-v1
def _store_fixed(s, version_id, fingerprint):
    s.add_all([AssetChunk(version_id=version_id, index=c.index, length=c.length, sha256=c.sha256) for c in fingerprint.chunks])


def fixed_evidence(view: DetectionView) -> ProfileEvidence:
    """The fixed profile's evidence in the per-profile shape, derived from the unchanged detection view."""
    return ProfileEvidence(profile_id=FIXED_ID, chunk_count=view.manifest.chunk_count, matches=[
        ProfileMatch(asset_id=m.asset_id, version_id=m.version_id, matched_bytes=m.matched_bytes,
                     matched_chunks=len(m.intervals), coverage=m.coverage, intervals=merged(m.intervals))
        for m in view.matches])


FIXED = register_profile(Profile(
    id=FIXED_ID, version=SPEC_VERSION,
    summary="Fixed 1,024-byte blocks from offset 0; SHA-256 per block; Merkle root over the ordered descriptors.",
    parameters=MappingProxyType({"chunk_size": CHUNK_SIZE, "chunk_hash": "SHA-256"}),
    fingerprint=fingerprint_bytes, store=_store_fixed,
    match=lambda s, fingerprint: fixed_evidence(detection.detect(s, fingerprint, 0))))


# ---------------------------------------------------------------------------------------------- rs-cdc-gear-v1
def _store_cdc(s, version_id, chunks):
    s.add_all([AssetCdcChunk(version_id=version_id, offset=c.offset, length=c.length, sha256=c.sha256) for c in chunks])


def synthetic_scope(s):
    """Visitor scans match the synthetic seed assets only. run_scan sets this flag on the session."""
    return (Asset.synthetic.is_(True),) if s.info.get("synthetic_only") else ()


def _match_cdc(s, chunks) -> ProfileEvidence:
    """Look up the upload's chunk hashes. Per version, the matched bytes are the union of the matched upload
    chunks' byte intervals, so a protected chunk that repeats in the registry never counts twice."""
    file_size = sum(c.length for c in chunks)
    outbound = defaultdict(list)
    for position, chunk in enumerate(chunks):
        outbound[chunk.sha256].append(position)
    keys = sorted(outbound)
    grouped: dict[str, tuple[str, set]] = {}
    references = 0
    for start in range(0, len(keys), CDC_LOOKUP_BATCH):
        # DISTINCT and LIMIT bound the rows in the database before any evidence is built.
        rows = s.execute(select(AssetCdcChunk.version_id, AssetVersion.asset_id, AssetCdcChunk.sha256, AssetCdcChunk.length)
            .select_from(AssetCdcChunk).join(AssetVersion, AssetCdcChunk.version_id == AssetVersion.id)
            .join(Asset, AssetVersion.asset_id == Asset.id)
            .where(Asset.retired.is_(False), Asset.current_version == AssetVersion.number, *synthetic_scope(s),
                   AssetCdcChunk.sha256.in_(keys[start:start + CDC_LOOKUP_BATCH]))
            .distinct().order_by(AssetCdcChunk.version_id, AssetCdcChunk.sha256)
            .limit(detection.MAX_REFERENCES - references + 1)).all()
        for version_id, asset_id, digest, length in rows:
            positions = [p for p in outbound[digest] if chunks[p].length == length]
            references += 1 + len(positions)
            if references > detection.MAX_REFERENCES:
                raise Indeterminate("EVIDENCE_LIMIT")
            if not positions:
                continue
            grouped.setdefault(version_id, (asset_id, set()))[1].update(positions)
            if len(grouped) > detection.MAX_MATCHED_VERSIONS:
                raise Indeterminate("EVIDENCE_LIMIT")
    matches = []
    for version_id, (asset_id, positions) in sorted(grouped.items()):
        runs = merged((chunks[p].offset, chunks[p].offset + chunks[p].length) for p in positions)
        matched = sum(end - begin for begin, end in runs)
        matches.append(ProfileMatch(asset_id=asset_id, version_id=version_id, matched_bytes=matched,
            matched_chunks=len(positions), coverage={"numerator": matched, "denominator": file_size}, intervals=runs))
    return ProfileEvidence(profile_id=CDC_ID, chunk_count=len(chunks), matches=matches)


CDC = register_profile(Profile(
    id=CDC_ID, version=cdc.CDC_PROFILE_VERSION,
    summary="Content-defined chunks (FastCDC, gear hash, normalized chunking); SHA-256 per chunk.",
    parameters=MappingProxyType({
        "min_size": cdc.MIN_SIZE, "normal_size": cdc.NORMAL_SIZE, "max_size": cdc.MAX_SIZE,
        "normalization_level": cdc.NORMALIZATION_LEVEL, "mask_s": f"0x{cdc.MASK_S:016x}", "mask_l": f"0x{cdc.MASK_L:016x}",
        "gear_table_sha256": cdc.gear_table_sha256(), "chunk_hash": "SHA-256"}),
    fingerprint=cdc.cdc_chunks, store=_store_cdc, match=_match_cdc))


# ---------------------------------------------------------------------------------------------- used by the services
def store_additional(s, version_id: str, data: bytes) -> None:
    """Fingerprint a new asset version with every registered profile other than the fixed one, whose rows the
    registry writes itself together with the version row."""
    for profile in registered():
        if profile.id != FIXED_ID:
            profile.store(s, version_id, profile.fingerprint(data))


def extend(s, data: bytes, view: DetectionView, profile_ids) -> DetectionView:
    """Add per-profile evidence to the fixed profile's detection view, which is passed in and kept as it is:
    ``matches`` stays exactly what ``detection.detect`` returned."""
    if FIXED_ID not in profile_ids:
        raise Indeterminate("UNSUPPORTED_PROFILE")
    evidence = [fixed_evidence(view)]
    for profile_id in profile_ids:
        if profile_id != FIXED_ID:
            profile = get(profile_id)
            evidence.append(profile.match(s, profile.fingerprint(data)))
    return view.model_copy(update={"profiles": evidence})


def version_profiles(s, versions) -> dict[str, list[VersionProfile]]:
    """For each given asset version, which profiles it carries. One grouped query for the CDC rows."""
    identifiers = [v.id for v in versions]
    counts = dict(s.execute(select(AssetCdcChunk.version_id, func.count()).where(
        AssetCdcChunk.version_id.in_(identifiers)).group_by(AssetCdcChunk.version_id)).all()) if identifiers else {}
    return {v.id: [VersionProfile(profile_id=FIXED_ID, fingerprinted=True, chunk_count=v.chunk_count),
                   VersionProfile(profile_id=CDC_ID, fingerprinted=v.id in counts, chunk_count=counts.get(v.id, 0))]
            for v in versions}
