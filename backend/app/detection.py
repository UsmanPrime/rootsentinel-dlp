"""Indexed raw-byte matching. No HTTP dependencies and no authorization verdicts."""
from collections import defaultdict

from sqlalchemy import select, tuple_

from .crypto import PROFILE_ID, Fingerprint
from .errors import Indeterminate
from .models import Asset, AssetChunk, AssetVersion
from .schemas import DetectionView, MatchView

MAX_MATCHED_VERSIONS = 1000
MAX_REFERENCES = 100000
LOOKUP_BATCH = 200


def detect(s, fingerprint: Fingerprint, revision: int) -> DetectionView:
    m = fingerprint.manifest
    if m.profile_id != PROFILE_ID:
        raise Indeterminate("UNSUPPORTED_PROFILE")
    active = (Asset.retired.is_(False), Asset.current_version == AssetVersion.number,
              AssetVersion.profile_id == m.profile_id)
    exact = s.execute(select(AssetVersion.id, AssetVersion.asset_id).join(Asset).where(
        *active, AssetVersion.file_size == m.file_size, AssetVersion.file_sha256 == m.file_sha256
    ).order_by(AssetVersion.id).limit(MAX_MATCHED_VERSIONS + 1)).all()
    if len(exact) > MAX_MATCHED_VERSIONS:
        raise Indeterminate("EVIDENCE_LIMIT")
    grouped = {v: {"asset": a, "exact": True, "blocks": []} for v, a in exact}
    outbound = defaultdict(list)
    for chunk in fingerprint.chunks:
        outbound[(chunk.sha256, chunk.length)].append(chunk.index)
    keys = sorted(outbound)
    refs = 0
    for start in range(0, len(keys), LOOKUP_BATCH):
        batch = keys[start:start + LOOKUP_BATCH]
        # Limit matching rows in the database before constructing any evidence.
        rows = s.execute(select(AssetChunk, AssetVersion.asset_id).join(AssetVersion).join(Asset).where(
            *active, tuple_(AssetChunk.sha256, AssetChunk.length).in_(batch)
        ).order_by(AssetChunk.version_id, AssetChunk.index).limit(MAX_REFERENCES - refs + 1)).all()
        sources = defaultdict(list)
        for chunk, asset_id in rows:
            refs += 1
            if refs > MAX_REFERENCES:
                raise Indeterminate("EVIDENCE_LIMIT")
            grouped.setdefault(chunk.version_id, {"asset": asset_id, "exact": False, "blocks": []})
            if len(grouped) > MAX_MATCHED_VERSIONS:
                raise Indeterminate("EVIDENCE_LIMIT")
            sources[(chunk.version_id, chunk.sha256, chunk.length)].append(chunk.index)
        for (version, digest, length), indices in sorted(sources.items()):
            destinations = outbound[(digest, length)]
            refs += len(destinations)
            if refs > MAX_REFERENCES:
                raise Indeterminate("EVIDENCE_LIMIT")
            grouped[version]["blocks"].append({"sha256": digest, "length": length,
                "source_indices": indices, "outbound_indices": destinations})
    matches = []
    for version, item in sorted(grouped.items()):
        # Fixed chunks never overlap. One destination index counts once per version,
        # independent of repeated protected-source occurrences or shared assets.
        intervals = sorted({(i * 1024, i * 1024 + block["length"])
                            for block in item["blocks"] for i in block["outbound_indices"]})
        matched = sum(end - begin for begin, end in intervals)
        matches.append(MatchView(asset_id=item["asset"], version_id=version, exact=item["exact"],
            matched_bytes=matched, coverage={"numerator": matched, "denominator": m.file_size},
            intervals=intervals, blocks=sorted(item["blocks"], key=lambda b: (b["sha256"], b["length"]))))
    return DetectionView(manifest=m.to_dict(), registry_revision=revision, matches=matches)
