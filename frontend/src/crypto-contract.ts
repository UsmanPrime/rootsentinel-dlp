/** Wire contract only. The backend remains the authoritative implementation. */
export type ProfileId = 'rs-fixed-sha256-v1';

export interface Manifest {
  spec_version: 1;
  profile_id: ProfileId;
  file_size: number;
  chunk_size: 1024;
  chunk_count: number;
  file_sha256: string;
  merkle_root: string;
}

export interface ChunkDescriptor {
  index: number;
  length: number;
  sha256: string;
}

export interface InclusionProof {
  spec_version: 1;
  profile_id: ProfileId;
  tree_size: number;
  chunk: ChunkDescriptor;
  siblings: string[];
}
