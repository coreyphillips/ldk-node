#!/usr/bin/env python3
"""Seed only published protocol vectors and empty synthetic storage records."""

from pathlib import Path


root = Path(__file__).resolve().parent
fixtures = root.parent / "vendor/lightning/src/ln/ffor/fixtures"
corpus = root / "corpus/chicory_ffor"
corpus.mkdir(parents=True, exist_ok=True)
for name in ("d1-init.bin", "d1-accept.bin", "d1-activate.bin", "d1-ack.bin", "sync-request.bin"):
    (corpus / name).write_bytes((fixtures / name).read_bytes())
(corpus / "empty-archive.bin").write_bytes(b"FFA2\x01\x00\x00\x00\x00")
(corpus / "empty-reestablish.bin").write_bytes(bytes(67))
print(f"Seeded {corpus} with seven public or empty records.")
