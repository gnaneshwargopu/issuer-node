# Issuer Node (Spec-Aligned MVP)

This repository implements a protocol-aligned Issuer core compatible with iden3-style claim structure.

## Implemented

- Full 8-slot claim structure (4 index + 4 value slots)
- Structured binary Poseidon hashing
- Sparse Merkle Tree (depth 32)
- Revocation tree
- Postgres-backed persistence
- State rebuild on startup

## Architecture

Claim → Commitment (Binary Poseidon Tree)  
Commitment → Claims SMT  
Claims Root → Roots Table  

## Status

MVP Protocol Layer  
Does NOT include:
- DID verification
- ZK proof verification
- Blockchain anchoring
- HTTP layer

## Tech Stack

- Rust (stable)
- poseidon-rs
- ff_ce
- Postgres