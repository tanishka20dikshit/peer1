#!/usr/bin/env python3
"""Update config.yaml introducer pubkeys from server_key JSON files.

Usage:
    python tools/update_pins.py \
        --config config.yaml \
        --key ws://127.0.0.1:8765=server_key_srv-a.json \
        --key ws://127.0.0.1:8766=server_key_srv-b.json \
        --key ws://127.0.0.1:8767=server_key_srv-c.json

The script loads the config, injects the pinned pubkeys for matching URLs,
and prints suggested --bootstrap arguments.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

import yaml


def load_pubkey(path: Path) -> str:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    try:
        return data["pub_spki_b64u"]
    except KeyError as exc:
        raise ValueError(f"{path} missing 'pub_spki_b64u'") from exc


def parse_key_spec(spec: str) -> tuple[str, Path]:
    if "=" not in spec:
        raise ValueError(f"expected url=path, got: {spec}")
    url, path = spec.split("=", 1)
    url = url.strip()
    if not url:
        raise ValueError(f"empty url in spec: {spec}")
    path = Path(path.strip()).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"key file not found: {path}")
    return url, path


def update_config(config_path: Path, keys: Dict[str, str]) -> Dict[str, str]:
    with config_path.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    if not isinstance(config, dict):
        raise ValueError("config.yaml must be a mapping")

    introducers = config.get("introducers")
    if introducers is None:
        introducers = []
        config["introducers"] = introducers
    if not isinstance(introducers, list):
        raise ValueError("'introducers' must be a list")

    applied = {}
    for entry in introducers:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if url in keys:
            entry["pubkey"] = keys[url]
            applied[url] = keys[url]

    with config_path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, sort_keys=False)

    return applied


def main() -> int:
    parser = argparse.ArgumentParser(description="Update introducer pins from server_key JSON files")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml (default: config.yaml)")
    parser.add_argument("--key", action="append", default=[], help="Mapping of url=path/to/server_key.json")
    args = parser.parse_args()

    if not args.key:
        parser.error("provide at least one --key url=path mapping")

    key_map: Dict[str, str] = {}
    for spec in args.key:
        url, path = parse_key_spec(spec)
        if url in key_map:
            parser.error(f"duplicate url provided: {url}")
        key_map[url] = load_pubkey(path)

    config_path = Path(args.config).resolve()
    if not config_path.exists():
        parser.error(f"config file not found: {config_path}")

    applied = update_config(config_path, key_map)

    if not applied:
        print("No matching introducers were updated.")
    else:
        print("Updated introducer pins:")
        for url, pub in applied.items():
            print(f"  {url} -> {pub}")

    print("\nSuggested --bootstrap arguments:")
    for url, pub in key_map.items():
        print(f"  {url}#{pub}")

    missing = [url for url in key_map.keys() if url not in applied]
    if missing:
        print("\nWARNING: the following URLs were not found in config introducers:")
        for url in missing:
            print(f"  {url}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
