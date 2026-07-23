#!/usr/bin/env python3
"""Validate and canonicalize per-scenario proof observations.

The workflow only publishes the sanitized, typed observations emitted by this
program. Raw test output is never copied into the proof artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


IDENTIFIER_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SENSITIVE_KEY_PATTERN = re.compile(
    r"(?:^|_)(?:api_key|authorization|code|cookie|credential|otp|password|private_key|secret|token)(?:_|$)"
)
SAFE_SENSITIVE_KEY_SUFFIXES = ("_count", "_present", "_sha256", "_status", "_verified")
SECRET_VALUE_PATTERNS = (
    re.compile(r"\blv_(?:live|test)_[A-Za-z0-9._~-]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)
MAX_CANONICAL_OBSERVATION_BYTES = 4096
MAX_DEPTH = 5
MAX_NODES = 128


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def strict_json(raw: bytes) -> Any:
    return json.loads(
        raw,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=reject_nonfinite,
    )


def load_document(path: Path) -> Any:
    return strict_json(path.read_bytes())


def validate_sanitized_observation(observation: Any) -> bytes:
    if not isinstance(observation, dict) or not observation:
        raise ValueError("observation must be a non-empty object")

    nodes = 0

    def visit(value: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NODES:
            raise ValueError("observation exceeds the node limit")
        if depth > MAX_DEPTH:
            raise ValueError("observation exceeds the depth limit")
        if value is None or isinstance(value, bool):
            return
        if isinstance(value, int) and not isinstance(value, bool):
            if abs(value) > 9_007_199_254_740_991:
                raise ValueError("observation integer is outside the exact JSON range")
            return
        if isinstance(value, float):
            raise ValueError("observation floats are not allowed")
        if isinstance(value, str):
            if len(value.encode("utf-8")) > 512 or any(ord(char) < 32 for char in value):
                raise ValueError("observation string is not bounded printable text")
            if any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS):
                raise ValueError("observation contains a secret-shaped string")
            return
        if isinstance(value, list):
            if len(value) > 32:
                raise ValueError("observation array exceeds the item limit")
            for item in value:
                visit(item, depth + 1)
            return
        if isinstance(value, dict):
            if len(value) > 32:
                raise ValueError("observation object exceeds the field limit")
            for key, item in value.items():
                if not isinstance(key, str) or IDENTIFIER_PATTERN.fullmatch(key) is None:
                    raise ValueError(f"observation key is not allowlisted: {key!r}")
                if SENSITIVE_KEY_PATTERN.search(key) and not key.endswith(SAFE_SENSITIVE_KEY_SUFFIXES):
                    raise ValueError(f"observation key could expose a secret: {key!r}")
                visit(item, depth + 1)
            return
        raise ValueError(f"observation contains unsupported value type: {type(value).__name__}")

    visit(observation, 0)
    encoded = canonical_json(observation)
    if len(encoded) > MAX_CANONICAL_OBSERVATION_BYTES:
        raise ValueError("canonical observation exceeds the byte limit")
    return encoded


def validate_contract(inventory: Any, contract: Any) -> tuple[list[str], dict[str, list[str]]]:
    if not isinstance(inventory, dict) or not isinstance(inventory.get("scenarios"), list):
        raise ValueError("inventory has no scenario array")
    if not isinstance(contract, dict) or set(contract) != {
        "evidence_kinds",
        "gate",
        "scenario_key_field",
        "scenarios",
        "schema_version",
    }:
        raise ValueError("typed evidence contract has an unexpected top-level shape")
    if contract["schema_version"] != 1 or contract["gate"] != inventory.get("gate"):
        raise ValueError("typed evidence contract header does not match the inventory")
    key_field = contract["scenario_key_field"]
    if (
        key_field not in {"id", "name"}
        or not isinstance(contract["scenarios"], dict)
        or not isinstance(contract["evidence_kinds"], dict)
    ):
        raise ValueError("typed evidence scenario key contract is invalid")

    kind_contracts: dict[str, dict[str, Any]] = {}
    for kind, kind_contract in contract["evidence_kinds"].items():
        if (
            not isinstance(kind, str)
            or IDENTIFIER_PATTERN.fullmatch(kind) is None
            or not isinstance(kind_contract, dict)
            or set(kind_contract) != {"exact_observation"}
            or kind_contract["exact_observation"] != {"verified": True}
        ):
            raise ValueError(f"typed evidence kind schema is invalid for {kind!r}")
        kind_contracts[kind] = kind_contract

    keys: list[str] = []
    seen: set[str] = set()
    for row in inventory["scenarios"]:
        if not isinstance(row, dict) or not isinstance(row.get(key_field), str):
            raise ValueError("inventory scenario key is invalid")
        scenario_key = row[key_field]
        if scenario_key in seen:
            raise ValueError(f"duplicate inventory scenario key: {scenario_key}")
        seen.add(scenario_key)
        keys.append(scenario_key)
    if set(contract["scenarios"]) != seen:
        missing = sorted(seen - set(contract["scenarios"]))
        extra = sorted(set(contract["scenarios"]) - seen)
        raise ValueError(f"typed evidence contract scenario mismatch: missing={missing}, extra={extra}")

    required: dict[str, list[str]] = {}
    for scenario_key in keys:
        kinds = contract["scenarios"][scenario_key]
        if (
            not isinstance(kinds, list)
            or not kinds
            or kinds != sorted(kinds)
            or len(kinds) != len(set(kinds))
            or any(not isinstance(kind, str) or IDENTIFIER_PATTERN.fullmatch(kind) is None for kind in kinds)
            or any(kind not in kind_contracts for kind in kinds)
        ):
            raise ValueError(f"typed evidence kinds are invalid for {scenario_key}")
        required[scenario_key] = kinds
    used_kinds = {kind for kinds in required.values() for kind in kinds}
    if set(kind_contracts) != used_kinds:
        raise ValueError("typed evidence kind schemas must exactly cover the required kinds")
    return sorted(keys), required


def verify(
    inventory_path: Path,
    contract_path: Path,
    observations_path: Path,
) -> tuple[bool, list[dict[str, Any]]]:
    inventory = load_document(inventory_path)
    contract = load_document(contract_path)
    scenario_keys, required = validate_contract(inventory, contract)
    kind_contracts = contract["evidence_kinds"]
    observed: dict[str, dict[str, dict[str, Any]]] = {key: {} for key in scenario_keys}

    if observations_path.exists():
        for line_number, line in enumerate(observations_path.read_bytes().splitlines(), start=1):
            if not line:
                raise ValueError(f"typed evidence line {line_number} is empty")
            record = strict_json(line)
            if canonical_json(record) != line:
                raise ValueError(f"typed evidence line {line_number} is not canonical JSON")
            if not isinstance(record, dict) or set(record) != {
                "kind",
                "observation",
                "observation_sha256",
                "scenario_key",
            }:
                raise ValueError(f"typed evidence line {line_number} has an unexpected shape")
            scenario_key = record["scenario_key"]
            kind = record["kind"]
            digest = record["observation_sha256"]
            if scenario_key not in required:
                raise ValueError(f"typed evidence references unknown scenario: {scenario_key}")
            if kind not in required[scenario_key]:
                raise ValueError(f"typed evidence kind {kind!r} is not required for {scenario_key}")
            if kind in observed[scenario_key]:
                raise ValueError(f"duplicate typed evidence kind {kind!r} for {scenario_key}")
            canonical_observation = validate_sanitized_observation(record["observation"])
            exact_observation = kind_contracts[kind]["exact_observation"]
            if record["observation"] != exact_observation:
                raise ValueError(f"typed evidence observation does not prove success for {scenario_key}/{kind}")
            expected_digest = hashlib.sha256(canonical_observation).hexdigest()
            if not isinstance(digest, str) or digest != expected_digest:
                raise ValueError(f"typed evidence digest mismatch for {scenario_key}/{kind}")
            observed[scenario_key][kind] = {
                "kind": kind,
                "observation": record["observation"],
                "observation_sha256": digest,
            }

    result: list[dict[str, Any]] = []
    complete = True
    for scenario_key in scenario_keys:
        kinds = observed[scenario_key]
        if sorted(kinds) != required[scenario_key]:
            complete = False
        result.append(
            {
                "evidence": [kinds[kind] for kind in sorted(kinds)],
                "scenario_key": scenario_key,
            }
        )
    return complete, result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--observations", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()
    try:
        complete, scenarios = verify(args.inventory, args.contract, args.observations)
        args.output.write_bytes(canonical_json({"complete": complete, "scenarios": scenarios}))
        if not complete and not args.allow_incomplete:
            raise ValueError("typed evidence is incomplete")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"typed evidence verification failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
