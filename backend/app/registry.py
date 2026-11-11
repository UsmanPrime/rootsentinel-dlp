"""Registry units of work. Immutable versions, explicit concurrency preconditions."""
from sqlalchemy import select, update

from . import profiles
from .crypto import Chunk, Fingerprint, Manifest, fingerprint_bytes
from .errors import DomainError, Indeterminate
from .models import Asset, AssetChunk, AssetVersion, RegistryRevision, RegistryState
from .schemas import AssetView, VersionView


def lock_state(s) -> RegistryState:
    # UPDATE acquires a writer/row lock on SQLite/PostgreSQL respectively. The
    # lock lives until commit; mutations and evaluations all use this order.
    result = s.execute(update(RegistryState).where(RegistryState.id == 1).values(revision=RegistryState.revision))
    if result.rowcount != 1:
        raise Indeterminate("REGISTRY_UNAVAILABLE")
    return s.get(RegistryState, 1, populate_existing=True)


def asset_view(asset) -> AssetView:
    return AssetView(**{k: getattr(asset, k) for k in AssetView.model_fields})


def manifest_for(version) -> Manifest:
    return Manifest(1, version.profile_id, version.file_size, 1024, version.chunk_count,
                    version.file_sha256, version.merkle_root)


def version_fingerprint(s, asset_id, version_id):
    version = s.get(AssetVersion, version_id)
    if version is None or version.asset_id != asset_id:
        raise DomainError("NOT_FOUND", 404)
    chunks = tuple(Chunk(c.index, c.length, c.sha256) for c in s.scalars(
        select(AssetChunk).where(AssetChunk.version_id == version.id).order_by(AssetChunk.index)))
    return version, Fingerprint(manifest_for(version), chunks)


def version_view(s, asset_id, version_id):
    version, fp = version_fingerprint(s, asset_id, version_id)
    return VersionView(id=version.id, asset_id=asset_id, number=version.number,
                       registry_revision=version.registry_revision, actor_id=version.actor_id,
                       created_at=version.created_at, manifest=fp.manifest.to_dict(),
                       chunks=[c.to_dict() for c in fp.chunks],
                       profiles=profiles.version_profiles(s, [version])[version.id])


def register(s, principal, label: str, data: bytes, asset_id=None, expected_version=None):
    principal.require("ADMIN")
    fp = fingerprint_bytes(data)
    if fp.manifest.file_size == 0:
        raise DomainError("EMPTY_PROTECTED_ASSET", 422)
    state = lock_state(s)
    if asset_id:
        asset = s.get(Asset, asset_id)
        if asset is None:
            raise DomainError("NOT_FOUND", 404)
        if asset.retired or asset.current_version != expected_version:
            raise DomainError("ASSET_VERSION_CONFLICT", 409)
        if s.scalar(select(AssetVersion.id).where(AssetVersion.asset_id == asset_id,
                    AssetVersion.file_size == fp.manifest.file_size, AssetVersion.file_sha256 == fp.manifest.file_sha256)):
            raise DomainError("DUPLICATE_ASSET_VERSION", 409)
        asset.current_version += 1
    else:
        if s.scalar(select(Asset.id).where(Asset.label == label)):
            raise DomainError("DUPLICATE_ASSET_LABEL", 409)
        asset = Asset(label=label, current_version=1)
        s.add(asset)
        s.flush()
    state.revision += 1
    revision = RegistryRevision(number=state.revision, actor_id=principal.id, asset_id=asset.id, action="REGISTER")
    s.add(revision)
    s.flush()
    manifest = fp.manifest
    version = AssetVersion(asset_id=asset.id, number=asset.current_version, registry_revision=state.revision,
                           actor_id=principal.id, profile_id=manifest.profile_id, file_size=manifest.file_size,
                           file_sha256=manifest.file_sha256, merkle_root=manifest.merkle_root, chunk_count=manifest.chunk_count)
    s.add(version)
    s.flush()
    s.add_all([AssetChunk(version_id=version.id, index=c.index, length=c.length, sha256=c.sha256) for c in fp.chunks])
    # Every other registered profile fingerprints the same bytes now: they are not kept after registration.
    profiles.store_additional(s, version.id, data)
    s.flush()
    return version_view(s, asset.id, version.id)


def add_missing_profiles(s, principal, asset_id, data: bytes):
    """Fingerprint the CURRENT version of an asset with the profiles it lacks, from bytes the caller still holds.

    The bytes must be the registered ones (size and SHA-256 are compared with the stored manifest). Only rows of
    the missing profiles are inserted; the version row and its fixed-profile rows are not touched. The registry
    revision advances, so approvals issued before the new fingerprints existed become stale. Returns the new
    revision, or None when nothing was missing."""
    principal.require("ADMIN")
    fp = fingerprint_bytes(data)
    state = lock_state(s)
    asset = s.get(Asset, asset_id)
    if asset is None:
        raise DomainError("NOT_FOUND", 404)
    version = s.scalar(select(AssetVersion).where(AssetVersion.asset_id == asset_id, AssetVersion.number == asset.current_version))
    if version is None or (version.file_size, version.file_sha256) != (fp.manifest.file_size, fp.manifest.file_sha256):
        raise DomainError("ASSET_CONTENT_MISMATCH", 409)
    if asset.retired or all(p.fingerprinted for p in profiles.version_profiles(s, [version])[version.id]):
        return None
    profiles.store_additional(s, version.id, data)
    state.revision += 1
    s.add(RegistryRevision(number=state.revision, actor_id=principal.id, asset_id=asset.id, action="PROFILE_ADDED"))
    s.flush()
    return state.revision


def retire(s, principal, asset_id):
    principal.require("ADMIN")
    state = lock_state(s)
    asset = s.get(Asset, asset_id)
    if asset is None:
        raise DomainError("NOT_FOUND", 404)
    if not asset.retired:
        asset.retired = True
        state.revision += 1
        s.add(RegistryRevision(number=state.revision, actor_id=principal.id, asset_id=asset.id, action="RETIRE"))
    return asset_view(asset)
