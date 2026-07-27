#!/usr/bin/env python3
"""Standard-library validator for the Develop Constitution.

This tool validates source structure and semantic invariants. It does not
verify cryptographic signatures or activate policy.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse


EXPECTED_TOP_LEVEL = {
    "api_version",
    "kind",
    "metadata",
    "defaults",
    "invariant",
    "scope",
    "lifecycle",
    "roles",
    "capabilities",
    "risk_classes",
    "maturity_levels",
    "clauses",
    "controls",
    "tests",
    "control_attestation_policy",
    "exception_policy",
    "amendment_policy",
    "incident_policy",
}
RISK_IDS = ("R0", "R1", "R2", "R3")
MATURITY_IDS = ("L0", "L1", "L2", "L3", "L4")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
SHA_RE = re.compile(r"[0-9a-f]{40}")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
EXPECTED_SCHEMAS = {
    "amendment-v1.schema.json",
    "activation-record-v1.schema.json",
    "capability-grant-v1.schema.json",
    "constitution-v1.schema.json",
    "control-attestation-v1.schema.json",
    "exception-v1.schema.json",
    "posture-v1.schema.json",
    "maturity-promotion-v1.schema.json",
    "release-manifest-v1.schema.json",
    "risk-rules-v1.schema.json",
    "signature-envelope-v1.schema.json",
    "trust-root-v1.schema.json",
}
RELEASE_FILE_SET = {
    "CONSTITUTION.md",
    "constitution/v1/constitution.json",
    "constitution/v1/risk-rules.json",
    "deployments/develop/posture.json",
    "schemas/activation-record-v1.schema.json",
    "schemas/amendment-v1.schema.json",
    "schemas/capability-grant-v1.schema.json",
    "schemas/constitution-v1.schema.json",
    "schemas/control-attestation-v1.schema.json",
    "schemas/exception-v1.schema.json",
    "schemas/maturity-promotion-v1.schema.json",
    "schemas/posture-v1.schema.json",
    "schemas/release-manifest-v1.schema.json",
    "schemas/risk-rules-v1.schema.json",
    "schemas/signature-envelope-v1.schema.json",
    "schemas/trust-root-v1.schema.json",
    "tools/constitutionctl.py",
    "trust/root.json",
}
FORBIDDEN_WORKER_CAPABILITIES = {
    "credential.consume",
    "github.push",
    "github.pull_request.create",
    "github.pull_request.review",
    "github.merge",
    "github.repository.settings",
    "deployment.execute",
    "governance.approve",
    "governance.activate",
    "worker.self_promote",
    "break_glass.invoke",
}
HUMAN_ONLY_CAPABILITIES = {
    "github.pull_request.review",
    "github.repository.settings",
    "governance.approve",
    "governance.activate",
    "worker.self_promote",
    "break_glass.invoke",
}
EXPECTED_ROLE_IDS = {
    "human_owner",
    "security_custodian",
    "control_plane",
    "worker",
    "verifier",
    "reviewer",
    "publication_broker",
    "merge_controller",
    "platform_administrator",
}
EXPECTED_CAPABILITY_IDS = {
    "repository.read",
    "task_clone.write",
    "candidate.execute",
    "git.commit",
    "task.admit",
    "lease.manage",
    "capability.grant",
    "evidence.attest",
    "network.egress",
    "credential.consume",
    "github.push",
    "github.pull_request.create",
    "github.pull_request.review",
    "github.merge",
    "github.repository.settings",
    "deployment.execute",
    "governance.propose",
    "governance.approve",
    "governance.activate",
    "audit.append",
    "worker.self_promote",
    "break_glass.invoke",
}


class ValidationError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value: str) -> None:
    raise ValidationError(f"unsupported JSON constant: {value}")


def load_json(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{path}: {exc}") from exc


def canonical_bytes(document: Any) -> bytes:
    return json.dumps(
        document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def document_digest(document: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(document)).hexdigest()


def resolve_schema_reference(root: dict[str, Any], reference: str) -> dict[str, Any]:
    if not reference.startswith("#/"):
        raise ValidationError(f"external schema reference is unsupported: {reference}")
    current: Any = root
    for component in reference[2:].split("/"):
        current = current[component.replace("~1", "/").replace("~0", "~")]
    if not isinstance(current, dict):
        raise ValidationError(f"schema reference is not an object: {reference}")
    return current


def schema_errors(
    instance: Any,
    schema: dict[str, Any],
    root_schema: dict[str, Any] | None = None,
    path: str = "$",
) -> list[str]:
    root = root_schema or schema
    if "$ref" in schema:
        return schema_errors(
            instance, resolve_schema_reference(root, schema["$ref"]), root, path
        )
    if "anyOf" in schema:
        alternatives = [
            schema_errors(instance, option, root, path)
            for option in schema["anyOf"]
        ]
        return [] if any(not errors for errors in alternatives) else [
            f"{path}: no anyOf alternative matched"
        ]

    errors: list[str] = []
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value is outside enum")

    expected_type = schema.get("type")
    type_checks = {
        "object": lambda value: isinstance(value, dict),
        "array": lambda value: isinstance(value, list),
        "string": lambda value: isinstance(value, str),
        "integer": lambda value: isinstance(value, int)
        and not isinstance(value, bool),
        "boolean": lambda value: isinstance(value, bool),
        "null": lambda value: value is None,
    }
    if expected_type and not type_checks[expected_type](instance):
        return errors + [f"{path}: expected {expected_type}"]

    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            errors.append(f"{path}: string is too short")
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            errors.append(f"{path}: string does not match pattern")
        if schema.get("format") == "date-time" and parse_utc(instance) is None:
            errors.append(f"{path}: expected UTC date-time")
        if schema.get("format") == "uri":
            parsed = urlparse(instance)
            if not parsed.scheme or not parsed.netloc:
                errors.append(f"{path}: expected absolute URI")

    if isinstance(instance, int) and not isinstance(instance, bool):
        if instance < schema.get("minimum", instance):
            errors.append(f"{path}: value below minimum")
        if instance > schema.get("maximum", instance):
            errors.append(f"{path}: value above maximum")

    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        if schema.get("uniqueItems"):
            encoded = [canonical_bytes(value) for value in instance]
            if len(encoded) != len(set(encoded)):
                errors.append(f"{path}: items are not unique")
        if "items" in schema:
            for index, value in enumerate(instance):
                errors.extend(
                    schema_errors(value, schema["items"], root, f"{path}[{index}]")
                )

    if isinstance(instance, dict):
        required = set(schema.get("required", []))
        for key in sorted(required - set(instance)):
            errors.append(f"{path}: missing required property {key}")
        properties = schema.get("properties", {})
        pattern_properties = schema.get("patternProperties", {})
        for key, value in instance.items():
            child_schema = properties.get(key)
            if child_schema is None:
                matches = [
                    candidate
                    for pattern, candidate in pattern_properties.items()
                    if re.fullmatch(pattern, key)
                ]
                child_schema = matches[0] if matches else None
            if child_schema is not None:
                errors.extend(
                    schema_errors(value, child_schema, root, f"{path}.{key}")
                )
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unknown property {key}")
            elif isinstance(schema.get("additionalProperties"), dict):
                errors.extend(
                    schema_errors(
                        value,
                        schema["additionalProperties"],
                        root,
                        f"{path}.{key}",
                    )
                )
        if "propertyNames" in schema:
            for key in instance:
                errors.extend(
                    schema_errors(
                        key, schema["propertyNames"], root, f"{path}.<property>"
                    )
                )
        if len(instance) < schema.get("minProperties", 0):
            errors.append(f"{path}: too few properties")
    return errors


SUPPORTED_SCHEMA_KEYS = {
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "title",
    "description",
    "type",
    "const",
    "enum",
    "anyOf",
    "properties",
    "patternProperties",
    "propertyNames",
    "additionalProperties",
    "required",
    "items",
    "minItems",
    "uniqueItems",
    "minProperties",
    "minLength",
    "minimum",
    "maximum",
    "pattern",
    "format",
}


def schema_definition_errors(
    schema: Any,
    path: str = "$",
    root_schema: dict[str, Any] | None = None,
) -> list[str]:
    if not isinstance(schema, dict):
        return [f"{path}: schema must be an object"]
    root = root_schema or schema
    errors = [
        f"{path}: unsupported schema keyword {key}"
        for key in schema
        if key not in SUPPORTED_SCHEMA_KEYS
    ]
    if schema.get("type") == "object" and "additionalProperties" not in schema:
        errors.append(f"{path}: object schema must declare additionalProperties")
    if "$ref" in schema:
        try:
            resolve_schema_reference(root, schema["$ref"])
        except (KeyError, TypeError, ValidationError) as exc:
            errors.append(f"{path}: invalid reference: {exc}")
    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (re.error, TypeError) as exc:
            errors.append(f"{path}: invalid pattern: {exc}")
    for key in ("properties", "patternProperties", "$defs"):
        for name, child in schema.get(key, {}).items():
            errors.extend(
                schema_definition_errors(child, f"{path}.{key}.{name}", root)
            )
    if isinstance(schema.get("additionalProperties"), dict):
        errors.extend(
            schema_definition_errors(
                schema["additionalProperties"],
                f"{path}.additionalProperties",
                root,
            )
        )
    if isinstance(schema.get("items"), dict):
        errors.extend(
            schema_definition_errors(schema["items"], f"{path}.items", root)
        )
    if isinstance(schema.get("propertyNames"), dict):
        errors.extend(
            schema_definition_errors(
                schema["propertyNames"], f"{path}.propertyNames", root
            )
        )
    for index, child in enumerate(schema.get("anyOf", [])):
        errors.extend(
            schema_definition_errors(child, f"{path}.anyOf[{index}]", root)
        )
    return errors


def require(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate_constitution(document: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(document, dict):
        return ["constitution must be an object"]
    require(set(document) == EXPECTED_TOP_LEVEL, "top-level fields must match v1", errors)
    if set(document) != EXPECTED_TOP_LEVEL:
        return errors

    require(document["api_version"] == "develop.cenetex/v1", "unsupported api_version", errors)
    require(document["kind"] == "Constitution", "kind must be Constitution", errors)
    require(document["defaults"] == {
        "decision": "deny",
        "unknown_risk": "R3",
        "unknown_capability": "deny",
        "control_failure": "deny",
        "signature_failure": "deny",
    }, "defaults must be strictly fail-closed", errors)

    roles = document["roles"]
    capabilities = document["capabilities"]
    controls = document["controls"]
    tests = document["tests"]
    require(isinstance(roles, dict) and "worker" in roles, "worker role is required", errors)
    require(isinstance(capabilities, dict) and capabilities, "capabilities are required", errors)
    require(set(roles) == EXPECTED_ROLE_IDS, "v1 role set must be exact", errors)
    require(
        set(capabilities) == EXPECTED_CAPABILITY_IDS,
        "v1 capability set must be exact",
        errors,
    )

    for role_id, role in roles.items():
        eligible = set(role.get("eligible_capabilities", []))
        denied = set(role.get("absolute_denials", []))
        require(not (eligible & denied), f"{role_id}: eligible and denied overlap", errors)
        for capability in eligible | denied:
            require(capability in capabilities, f"{role_id}: unknown capability {capability}", errors)
        for separation in role.get("separated_from", []):
            require(
                separation.get("role") in roles,
                f"{role_id}: unknown separated role {separation.get('role')}",
                errors,
            )

    worker = roles.get("worker", {})
    worker_denials = set(worker.get("absolute_denials", []))
    require(
        FORBIDDEN_WORKER_CAPABILITIES <= worker_denials,
        "worker absolute denials are incomplete",
        errors,
    )
    for capability_id in worker.get("eligible_capabilities", []):
        capability = capabilities.get(capability_id, {})
        require(
            capability.get("external") is False,
            f"worker cannot receive external capability {capability_id}",
            errors,
        )
        require(
            capability.get("effect") in {"read", "write", "execute", "propose"},
            f"worker capability has privileged effect {capability_id}",
            errors,
        )
    require(
        roles.get("reviewer", {}).get("principal_kinds") == ["human"],
        "approval reviewer must be human-only",
        errors,
    )

    for capability_id, capability in capabilities.items():
        ttl = capability.get("maximum_ttl_seconds")
        bindings = capability.get("required_bindings")
        require(
            isinstance(ttl, int) and 0 <= ttl <= 86400,
            f"{capability_id}: invalid TTL",
            errors,
        )
        require(
            isinstance(bindings, list) and len(bindings) == len(set(bindings)),
            f"{capability_id}: bindings must be a unique list",
            errors,
        )
        if capability.get("external"):
            require(
                capability.get("brokered") is True,
                f"{capability_id}: external capability must be brokered",
                errors,
            )
            require(
                "expires_at" in bindings,
                f"{capability_id}: external capability must expire",
                errors,
            )

    risks = document["risk_classes"]
    require(tuple(risks) == RISK_IDS, "risk classes must be ordered R0 through R3", errors)
    require(
        [risks[risk]["rank"] for risk in RISK_IDS] == list(range(4)),
        "risk ranks must be contiguous",
        errors,
    )
    require(
        risks["R3"].get("minimum_maturity_for_automated_publication") is None,
        "R3 must never be automated",
        errors,
    )

    levels = document["maturity_levels"]
    require(tuple(levels) == MATURITY_IDS, "maturity levels must be ordered L0 through L4", errors)
    require(
        [levels[level]["rank"] for level in MATURITY_IDS] == list(range(5)),
        "maturity ranks must be contiguous",
        errors,
    )
    previous_ceiling: set[str] = set()
    previous_controls: set[str] = set()
    mutation_ranks = {"none": -1, "R0": 0, "R1": 1, "R2": 2}
    previous_mutation_rank = -1
    for level_id, level in levels.items():
        require(
            level.get("promotion_approvals", 0) >= 2,
            f"{level_id}: promotion needs two human approvals",
            errors,
        )
        ceiling = set(level.get("nonhuman_capability_ceiling", []))
        require(ceiling <= set(capabilities), f"{level_id}: unknown ceiling capability", errors)
        require(
            not (ceiling & HUMAN_ONLY_CAPABILITIES),
            f"{level_id}: human-only capability in non-human ceiling",
            errors,
        )
        require(
            previous_ceiling <= ceiling,
            f"{level_id}: maturity capability ceiling is not monotonic",
            errors,
        )
        mutation_risk = level.get("maximum_autonomous_mutation_risk")
        require(mutation_risk in mutation_ranks, f"{level_id}: invalid mutation risk", errors)
        if mutation_risk in mutation_ranks:
            require(
                mutation_ranks[mutation_risk] >= previous_mutation_rank,
                f"{level_id}: mutation risk ceiling is not monotonic",
                errors,
            )
            previous_mutation_rank = mutation_ranks[mutation_risk]
        previous_ceiling = ceiling
        for control_id in level.get("required_controls", []):
            require(control_id in controls, f"{level_id}: unknown control {control_id}", errors)
        level_controls = set(level.get("required_controls", []))
        require(
            previous_controls <= level_controls,
            f"{level_id}: required controls are not cumulative",
            errors,
        )
        previous_controls = level_controls
    require(
        set(levels["L0"].get("nonhuman_capability_ceiling", []))
        == {"repository.read"},
        "L0 must permit only repository.read to non-human principals",
        errors,
    )

    lifecycle = document["lifecycle"]
    states = set(lifecycle.get("states", []))
    terminal = set(lifecycle.get("terminal_states", []))
    transitions = lifecycle.get("transitions", {})
    require(set(transitions) == states, "every lifecycle state needs transitions", errors)
    require(terminal <= states, "terminal states must be lifecycle states", errors)
    for source, targets in transitions.items():
        require(set(targets) <= states, f"{source}: transition targets unknown state", errors)
        if source in terminal:
            require(targets == [], f"{source}: terminal state has outgoing transition", errors)

    clauses = document["clauses"]
    for clause_id, clause in clauses.items():
        require(clause.get("accountable_role") in roles, f"{clause_id}: unknown owner", errors)
        require(clause.get("unwaivable") is True, f"{clause_id}: v1 clause must be unwaivable", errors)
        require(clause.get("on_violation", {}).get("decision") == "deny", f"{clause_id}: violation must deny", errors)
        require(clause.get("on_violation", {}).get("demote_to") == "L0", f"{clause_id}: violation must demote L0", errors)
        for role_id in clause.get("subjects", []):
            require(role_id in roles, f"{clause_id}: unknown subject {role_id}", errors)
        for control_id in clause.get("control_ids", []):
            require(control_id in controls, f"{clause_id}: unknown control {control_id}", errors)
        for test_id in clause.get("test_ids", []):
            require(test_id in tests, f"{clause_id}: unknown test {test_id}", errors)
        require(bool(clause.get("control_ids")), f"{clause_id}: control required", errors)
        require(bool(clause.get("test_ids")), f"{clause_id}: adversarial test required", errors)

    for control_id, control in controls.items():
        require(control.get("kind") == "preventive", f"{control_id}: must be preventive", errors)
        require(control.get("owner") in roles, f"{control_id}: unknown owner", errors)
        require(control.get("fail_mode") in {"deny", "terminate"}, f"{control_id}: unsafe fail mode", errors)

    for test_id, test in tests.items():
        require(
            test.get("tier") in {"model", "integration", "platform"},
            f"{test_id}: invalid test tier",
            errors,
        )
        require(bool(test.get("runner")), f"{test_id}: runner is required", errors)
        require(
            test.get("evidence_schema")
            == "schemas/control-attestation-v1.schema.json",
            f"{test_id}: control attestation evidence is required",
            errors,
        )

    attestation_policy = document["control_attestation_policy"]
    require(
        set(attestation_policy.get("required_bindings", []))
        == {
            "constitution_manifest_digest",
            "control_id",
            "implementation_digest",
            "environment_digest",
            "repository",
            "risk_class",
            "capability",
            "runner_identity",
            "verifier_identity",
            "test_evidence_digest",
            "result",
            "observed_at",
            "expires_at",
            "verifier_signature_envelope_digest",
        },
        "control attestation bindings must match v1",
        errors,
    )
    require(
        document["exception_policy"].get("unwaivable_clause_exceptions") == "deny",
        "unwaivable clause exceptions must be denied",
        errors,
    )
    require(
        document["amendment_policy"].get("governing_policy") == "previous-active-constitution",
        "previous constitution must govern amendments",
        errors,
    )
    require(
        document["amendment_policy"].get("minimum_human_approvals", 0) >= 2,
        "amendments need two human approvals",
        errors,
    )
    require(
        document["amendment_policy"].get("agents_may_activate") is False,
        "agents must not activate amendments",
        errors,
    )
    return errors


def validate_risk_rules(document: Any, constitution: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(document.get("kind") == "RiskRules", "risk rules kind is invalid", errors)
    require(document.get("defaults") == {
        "unknown_path": "R3",
        "unknown_change_kind": "R3",
        "ambiguous_classification": "highest",
    }, "risk defaults must fail to R3", errors)
    valid_risks = set(constitution["risk_classes"])
    require(
        document.get("repository_floors", {}).get("cenetex/agentd") == "R3",
        "agentd repository floor must be R3",
        errors,
    )
    require(
        document.get("repository_floors", {}).get(
            "cenetex/develop-constitution"
        )
        == "R3",
        "constitution repository floor must be R3",
        errors,
    )
    path_patterns: set[str] = set()
    for rule in document.get("path_rules", []):
        pattern = rule.get("pattern", "")
        require(pattern not in path_patterns, f"duplicate risk pattern: {pattern}", errors)
        path_patterns.add(pattern)
        require(pattern and not pattern.startswith("/"), f"unsafe risk pattern: {pattern}", errors)
        require(".." not in PurePosixPath(pattern).parts, f"escaping risk pattern: {pattern}", errors)
        require(rule.get("risk") in valid_risks, f"unknown path risk: {rule.get('risk')}", errors)
    change_kinds: set[str] = set()
    for rule in document.get("semantic_rules", []):
        change_kind = rule.get("change_kind")
        require(
            change_kind not in change_kinds,
            f"duplicate semantic change kind: {change_kind}",
            errors,
        )
        change_kinds.add(change_kind)
        require(rule.get("minimum_risk") in valid_risks, "unknown semantic risk", errors)
    return errors


def validate_posture(document: Any, constitution: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    require(document.get("kind") == "PostureActivation", "posture kind is invalid", errors)
    require(document.get("workspace_id") == "develop", "posture workspace is invalid", errors)
    require(
        document.get("baseline_maturity_level") == "L0",
        "v1 baseline posture must remain L0",
        errors,
    )
    require(document.get("mode") == "quarantine", "posture mode mismatch", errors)
    source_digest = document.get("constitution_source_digest")
    manifest_digest = document.get("release_manifest_digest")
    expected = document_digest(constitution)
    if document.get("status") == "proposed":
        require(source_digest in {"PENDING", expected}, "proposed source digest mismatch", errors)
        require(manifest_digest is None, "proposed posture cannot bind a release", errors)
        require(document.get("effective_at") is None, "proposed posture cannot be effective", errors)
        require(document.get("sequence") == 0, "proposed posture sequence must be zero", errors)
        require(
            document.get("previous_posture_digest") is None,
            "proposed posture cannot name a predecessor",
            errors,
        )
        require(
            document.get("activation_envelope_digest") is None,
            "proposed posture cannot bind activation",
            errors,
        )
        require(
            document.get("control_attestation_set_digest") is None,
            "proposed posture cannot bind control attestations",
            errors,
        )
        require(
            document.get("scoped_authorizations") == [],
            "proposed posture cannot grant scoped authority",
            errors,
        )
    else:
        require(
            document.get("status") == "active",
            "only proposed or active posture is valid",
            errors,
        )
        require(
            constitution.get("metadata", {}).get("status") == "ratified",
            "active posture requires a ratified constitution",
            errors,
        )
        require(source_digest == expected, "active source digest mismatch", errors)
        require(
            isinstance(manifest_digest, str)
            and DIGEST_RE.fullmatch(manifest_digest) is not None,
            "active posture needs release manifest digest",
            errors,
        )
        require(parse_utc(document.get("effective_at")) is not None, "active posture needs UTC effective_at", errors)
        require(
            isinstance(document.get("sequence"), int)
            and document["sequence"] >= 1,
            "active posture needs a positive sequence",
            errors,
        )
        for field in (
            "previous_posture_digest",
            "activation_envelope_digest",
            "control_attestation_set_digest",
        ):
            value = document.get(field)
            require(
                isinstance(value, str)
                and DIGEST_RE.fullmatch(value) is not None,
                f"active posture needs {field}",
                errors,
            )
    capabilities = set(constitution["capabilities"])
    for capability in document.get("tightening_denials", []):
        require(capability in capabilities, f"unknown posture denial {capability}", errors)
    controls = set(constitution["controls"])
    gaps = set(document.get("known_control_gaps", []))
    require(gaps <= controls, "posture contains unknown control gap", errors)
    scopes: set[tuple[str, str, str, str]] = set()
    risk_ranks = {risk: index for index, risk in enumerate(RISK_IDS)}
    mutation_ranks = {"none": -1, "R0": 0, "R1": 1, "R2": 2}
    for authorization in document.get("scoped_authorizations", []):
        capability = authorization.get("capability")
        level_id = authorization.get("maturity_level")
        risk = authorization.get("risk_class")
        scope = (
            str(authorization.get("control_plane_digest")),
            str(authorization.get("repository")),
            str(risk),
            str(capability),
        )
        require(scope not in scopes, "duplicate scoped authorization", errors)
        scopes.add(scope)
        require(capability in capabilities, "unknown scoped capability", errors)
        require(level_id in MATURITY_IDS[1:], "scoped maturity must exceed L0", errors)
        require(risk in RISK_IDS, "unknown scoped risk", errors)
        for field in (
            "control_plane_digest",
            "promotion_evidence_digest",
            "control_attestation_set_digest",
        ):
            value = authorization.get(field)
            require(
                isinstance(value, str)
                and DIGEST_RE.fullmatch(value) is not None,
                f"invalid scoped digest: {field}",
                errors,
            )
        require(
            REPOSITORY_RE.fullmatch(str(authorization.get("repository", "")))
            is not None,
            "invalid scoped repository",
            errors,
        )
        require(
            parse_utc(authorization.get("expires_at")) is not None,
            "invalid scoped expiry",
            errors,
        )
        if level_id in constitution["maturity_levels"]:
            level = constitution["maturity_levels"][level_id]
            require(
                capability in level["nonhuman_capability_ceiling"],
                "scope exceeds maturity capability ceiling",
                errors,
            )
            if risk in risk_ranks:
                require(
                    risk_ranks[risk]
                    <= mutation_ranks[level["maximum_autonomous_mutation_risk"]],
                    "scope exceeds maturity risk ceiling",
                    errors,
                )
            required = set(level["required_controls"])
            require(
                not (required & gaps),
                "active scoped posture has required control gaps",
                errors,
            )
    return errors


def validate_trust_root(
    document: Any,
    constitution: dict[str, Any],
    posture: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    require(document.get("kind") == "TrustRoot", "trust root kind is invalid", errors)
    principals = document.get("principals", [])
    active = [
        principal for principal in principals if principal.get("status") == "active"
    ]
    require(
        len({principal.get("principal_id") for principal in principals})
        == len(principals),
        "trust principal IDs must be unique",
        errors,
    )
    require(
        len({principal.get("key_id") for principal in principals}) == len(principals),
        "trust key IDs must be unique",
        errors,
    )
    if document.get("status") == "unratified":
        require(document.get("sequence") == 0, "unratified root sequence must be zero", errors)
        require(not principals, "unratified root cannot invent principals", errors)
        require(
            document.get("predecessor_root_digest") is None,
            "unratified root cannot name a predecessor",
            errors,
        )
        require(document.get("effective_at") is None, "unratified root cannot be effective", errors)
        require(document.get("expires_at") is None, "unratified root cannot expire", errors)
        require(
            constitution["metadata"]["status"] == "proposed",
            "unratified root requires proposed constitution",
            errors,
        )
        require(
            posture.get("status") == "proposed",
            "unratified root requires proposed posture",
            errors,
        )
    elif document.get("status") == "active":
        require(
            len(active) >= document.get("threshold", 2),
            "active trust root does not meet threshold",
            errors,
        )
        effective = parse_utc(document.get("effective_at"))
        expires = parse_utc(document.get("expires_at"))
        require(effective is not None, "active trust root needs effective_at", errors)
        require(expires is not None, "active trust root needs expires_at", errors)
        if effective is not None and expires is not None:
            require(effective < expires, "trust root lifetime is invalid", errors)
    else:
        require(
            document.get("status") == "superseded",
            "unknown trust root status",
            errors,
        )
    allowed_algorithms = set(document.get("allowed_signature_algorithms", []))
    for principal in principals:
        require(
            principal.get("algorithm") in allowed_algorithms,
            "principal uses disallowed signature algorithm",
            errors,
        )
    return errors


def transition_allowed(constitution: dict[str, Any], source: str, target: str) -> bool:
    transitions = constitution["lifecycle"]["transitions"]
    return source in transitions and target in transitions[source]


def capability_eligible(constitution: dict[str, Any], role_id: str, capability_id: str) -> bool:
    role = constitution.get("roles", {}).get(role_id)
    if not role or capability_id not in constitution.get("capabilities", {}):
        return False
    if capability_id in role.get("absolute_denials", []):
        return False
    return capability_id in role.get("eligible_capabilities", [])


def effective_capability_decision(
    constitution: dict[str, Any],
    posture: dict[str, Any],
    role_id: str,
    principal_kind: str,
    capability_id: str,
    repository: str,
    trusted_risk: str,
    control_plane_digest: str,
    now: datetime,
) -> tuple[str, str]:
    if validate_posture(posture, constitution):
        return "deny", "invalid-posture"
    if posture.get("status") != "active":
        return "deny", "posture-inactive"
    effective_at = parse_utc(posture.get("effective_at"))
    if effective_at is None or now < effective_at:
        return "deny", "posture-not-effective"
    if not capability_eligible(constitution, role_id, capability_id):
        return "deny", "role-ineligible"
    if principal_kind not in constitution["roles"][role_id]["principal_kinds"]:
        return "deny", "principal-kind-ineligible"
    if capability_id in posture.get("tightening_denials", []):
        return "deny", "posture-denial"
    if principal_kind == "human":
        return "review", "external-human-authorization-required"
    baseline = constitution["maturity_levels"]["L0"]
    if capability_id in baseline["nonhuman_capability_ceiling"]:
        return "eligible", "explicit-task-grant-still-required"
    matching = [
        authorization
        for authorization in posture.get("scoped_authorizations", [])
        if authorization.get("repository") == repository
        and authorization.get("risk_class") == trusted_risk
        and authorization.get("capability") == capability_id
        and authorization.get("control_plane_digest") == control_plane_digest
        and (
            parse_utc(authorization.get("expires_at")) is not None
            and now < parse_utc(authorization["expires_at"])
        )
    ]
    if len(matching) != 1:
        return "deny", "no-exact-scoped-authorization"
    return "eligible", "explicit-task-grant-still-required"


def exception_decision(constitution: dict[str, Any], proposal: dict[str, Any]) -> tuple[str, str]:
    clause = constitution.get("clauses", {}).get(proposal.get("clause_id"))
    if clause is None:
        return "deny", "unknown-clause"
    if clause.get("unwaivable"):
        return "deny", "unwaivable-clause"
    paths = proposal.get("paths", [])
    if not paths or any(any(character in path for character in "*?[") or ".." in PurePosixPath(path).parts for path in paths):
        return "deny", "inexact-scope"
    return "review", "detached-human-approval-required"


def approval_set_decision(
    subject_sha: str,
    approvals: list[dict[str, Any]],
    required_humans: int,
    disallowed_principals: set[str] | None = None,
) -> tuple[str, str]:
    disallowed = disallowed_principals or set()
    humans: set[str] = set()
    for approval in approvals:
        principal = approval.get("principal")
        if approval.get("head_sha") != subject_sha:
            return "deny", "stale-sha"
        if principal in disallowed:
            return "deny", "conflicted-principal"
        if approval.get("principal_kind") != "human":
            return "deny", "non-human-approval"
        if not principal:
            return "deny", "missing-principal"
        humans.add(principal)
    if len(humans) < required_humans:
        return "deny", "approval-threshold"
    return "review", "detached-signature-verification-required"


def amendment_decision(
    constitution: dict[str, Any],
    active_manifest_digest: str,
    proposal: dict[str, Any],
    approvals: list[dict[str, Any]],
    now: datetime,
    verified_classification: str | None = None,
) -> tuple[str, str]:
    expected_fields = {
        "api_version",
        "kind",
        "issue",
        "requesting_principal",
        "base_manifest_digest",
        "candidate_manifest_digest",
        "classification",
        "classification_evidence_digest",
        "proposed_at",
        "activate_after",
        "authority_delta",
        "independent_security_review_digest",
        "threat_model",
        "migration",
        "rollback",
        "alternatives",
    }
    if set(proposal) != expected_fields:
        return "deny", "invalid-amendment-shape"
    if proposal.get("base_manifest_digest") != active_manifest_digest:
        return "deny", "predecessor-mismatch"
    candidate = proposal.get("candidate_manifest_digest")
    if not isinstance(candidate, str) or candidate == active_manifest_digest:
        return "deny", "invalid-candidate"
    classification = proposal.get("classification")
    if classification not in {"tightening", "neutral", "expansion"}:
        return "deny", "unknown-amendment-class"
    if verified_classification != classification:
        return "deny", "classification-unverified"
    if not DIGEST_RE.fullmatch(
        str(proposal.get("independent_security_review_digest", ""))
    ):
        return "deny", "independent-review-missing"
    required = constitution["amendment_policy"]["minimum_human_approvals"]
    approval_result = approval_set_decision(
        candidate,
        approvals,
        required,
        {proposal.get("requesting_principal", "")},
    )
    if approval_result[0] == "deny":
        return approval_result
    if classification == "expansion":
        proposed_at = parse_utc(proposal.get("proposed_at"))
        activate_after = parse_utc(proposal.get("activate_after"))
        cooling = timedelta(
            seconds=constitution["amendment_policy"][
                "expansion_cooling_period_seconds"
            ]
        )
        if (
            proposed_at is None
            or activate_after is None
            or activate_after < proposed_at + cooling
            or now < activate_after
        ):
            return "deny", "cooling-period"
    return "review", "external-ratification-required"


def maturity_promotion_decision(
    constitution: dict[str, Any],
    posture: dict[str, Any],
    proposal: dict[str, Any],
    now: datetime,
) -> tuple[str, str]:
    """Screen a scoped promotion proposal without authorizing it."""
    if validate_posture(posture, constitution):
        return "deny", "invalid-posture"
    if posture.get("status") != "active":
        return "deny", "posture-inactive"
    if proposal.get("workspace_id") != "develop":
        return "deny", "workspace-mismatch"
    if proposal.get("previous_posture_digest") != document_digest(posture):
        return "deny", "predecessor-posture-mismatch"
    if (
        proposal.get("requesting_component_digest") is not None
        and proposal.get("requesting_component_digest")
        == proposal.get("control_plane_digest")
    ):
        return "deny", "self-promotion"
    repository = proposal.get("repository")
    risk = proposal.get("risk_class")
    capability = proposal.get("capability")
    scope_matches = [
        authorization
        for authorization in posture.get("scoped_authorizations", [])
        if authorization.get("control_plane_digest")
        == proposal.get("control_plane_digest")
        and authorization.get("repository") == repository
        and authorization.get("risk_class") == risk
        and authorization.get("capability") == capability
    ]
    current = scope_matches[0]["maturity_level"] if scope_matches else "L0"
    requested = proposal.get("requested_maturity")
    if proposal.get("current_maturity") != current:
        return "deny", "current-maturity-mismatch"
    if (
        requested not in MATURITY_IDS
        or MATURITY_IDS.index(requested) != MATURITY_IDS.index(current) + 1
    ):
        return "deny", "promotion-must-be-one-level"
    level = constitution["maturity_levels"][requested]
    if capability not in level["nonhuman_capability_ceiling"]:
        return "deny", "capability-exceeds-level"
    risk_ranks = {"R0": 0, "R1": 1, "R2": 2, "R3": 3}
    mutation_ranks = {"none": -1, "R0": 0, "R1": 1, "R2": 2}
    if (
        risk not in risk_ranks
        or risk_ranks[risk]
        > mutation_ranks[level["maximum_autonomous_mutation_risk"]]
    ):
        return "deny", "risk-exceeds-level"
    started = parse_utc(proposal.get("observation_started_at"))
    ended = parse_utc(proposal.get("observation_ended_at"))
    if started is None or ended is None or ended < started:
        return "deny", "invalid-observation-window"
    if ended - started < timedelta(days=level["minimum_observation_days"]):
        return "deny", "observation-window-too-short"
    if proposal.get("governed_task_count", -1) < level["minimum_governed_tasks"]:
        return "deny", "insufficient-governed-tasks"
    if proposal.get("repository_count", 0) < level.get("minimum_repositories", 1):
        return "deny", "insufficient-repositories"
    required_adversarial = max(
        constitution["maturity_levels"][item].get("minimum_adversarial_tests", 0)
        for item in MATURITY_IDS[: MATURITY_IDS.index(requested) + 1]
    )
    if proposal.get("adversarial_test_count", -1) < required_adversarial:
        return "deny", "insufficient-adversarial-tests"
    if proposal.get("integrity_incident_count") != 0:
        return "deny", "integrity-incident"
    if proposal.get("open_high_critical_findings") != 0:
        return "deny", "open-security-findings"
    proposed = parse_utc(proposal.get("proposed_at"))
    activate_after = parse_utc(proposal.get("activate_after"))
    cooling = timedelta(
        seconds=constitution["amendment_policy"][
            "expansion_cooling_period_seconds"
        ]
    )
    if (
        proposed is None
        or activate_after is None
        or activate_after < proposed + cooling
        or now < activate_after
    ):
        return "deny", "cooling-period"
    for field in (
        "task_evidence_digest",
        "incident_register_digest",
        "control_attestation_set_digest",
        "independent_security_review_digest",
        "approval_envelope_digest",
    ):
        if DIGEST_RE.fullmatch(str(proposal.get(field, ""))) is None:
            return "deny", f"missing-evidence:{field}"
    return "review", "external-ratification-required"


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        return None


def release_activation_decision(
    trust_root: dict[str, Any],
    envelope: dict[str, Any],
    manifest: dict[str, Any],
    current_manifest_digest: str | None,
    current_sequence: int,
    now: datetime,
) -> tuple[str, str]:
    """Perform structural screening only; never authorize activation."""
    if trust_root.get("status") != "active":
        return "deny", "trust-root-unratified"
    root_effective = parse_utc(trust_root.get("effective_at"))
    root_expires = parse_utc(trust_root.get("expires_at"))
    if (
        root_effective is None
        or root_expires is None
        or not (root_effective <= now < root_expires)
    ):
        return "deny", "trust-root-inactive"
    manifest_errors = release_manifest_errors(
        manifest, current_manifest_digest, current_sequence
    )
    if manifest_errors:
        return "deny", "invalid-release-manifest"
    manifest_digest = document_digest(manifest)
    if envelope.get("payload_digest") != manifest_digest:
        return "deny", "manifest-digest-mismatch"
    if envelope.get("purpose") != "constitution-release":
        return "deny", "signature-purpose-mismatch"
    if envelope.get("domain") != "develop.cenetex/governance/v1":
        return "deny", "signature-domain-mismatch"
    if envelope.get("workspace_id") != manifest.get("workspace_id"):
        return "deny", "signature-workspace-mismatch"
    if envelope.get("target_id") != manifest.get("target_id"):
        return "deny", "signature-target-mismatch"
    if envelope.get("sequence") != manifest.get("sequence"):
        return "deny", "signature-sequence-mismatch"
    if envelope.get("trust_root_digest") != document_digest(trust_root):
        return "deny", "signature-root-mismatch"
    created = parse_utc(envelope.get("created_at"))
    expires = parse_utc(envelope.get("expires_at"))
    if created is None or expires is None or not (created <= now < expires):
        return "deny", "signature-envelope-inactive"
    trusted = {
        principal["key_id"]: (
            principal["principal_id"],
            principal["algorithm"],
        )
        for principal in trust_root.get("principals", [])
        if principal.get("status") == "active"
    }
    signers: set[str] = set()
    for signature in envelope.get("signatures", []):
        key_id = signature.get("key_id")
        principal_id = signature.get("principal_id")
        if trusted.get(key_id) != (
            principal_id,
            signature.get("algorithm"),
        ):
            return "deny", "untrusted-signature-metadata"
        signers.add(principal_id)
    if len(signers) < trust_root.get("threshold", 2):
        return "deny", "signature-threshold"
    return "review", "external-cryptographic-verification-required"


def release_manifest_errors(
    manifest: dict[str, Any],
    current_manifest_digest: str | None,
    current_sequence: int,
) -> list[str]:
    errors: list[str] = []
    require(manifest.get("kind") == "ReleaseManifest", "invalid manifest kind", errors)
    require(manifest.get("workspace_id") == "develop", "invalid manifest workspace", errors)
    require(
        manifest.get("target_id") == "develop-policy-store",
        "invalid manifest target",
        errors,
    )
    require(
        manifest.get("sequence") == current_sequence + 1,
        "manifest sequence is not monotonic",
        errors,
    )
    require(
        manifest.get("predecessor_manifest_digest") == current_manifest_digest,
        "manifest predecessor mismatch",
        errors,
    )
    require(
        manifest.get("canonicalization")
        == "sorted-keys-utf8-no-whitespace-v1",
        "unsupported manifest canonicalization",
        errors,
    )
    require(
        manifest.get("source_repository") == "cenetex/develop-constitution",
        "invalid source repository",
        errors,
    )
    require(
        parse_utc(manifest.get("created_at")) is not None,
        "invalid manifest created_at",
        errors,
    )
    for field in ("source_commit", "source_tree"):
        require(
            isinstance(manifest.get(field), str)
            and SHA_RE.fullmatch(manifest[field]) is not None,
            f"invalid manifest SHA: {field}",
            errors,
        )
    require(
        isinstance(manifest.get("constitution_document_digest"), str)
        and DIGEST_RE.fullmatch(manifest["constitution_document_digest"]) is not None,
        "invalid constitution source digest",
        errors,
    )
    files = manifest.get("files")
    require(isinstance(files, dict), "manifest files must be an object", errors)
    if not isinstance(files, dict):
        return errors
    require(
        set(files) == RELEASE_FILE_SET,
        "manifest file set must match the release profile",
        errors,
    )
    for path, metadata in files.items():
        require(path in RELEASE_FILE_SET, f"unsafe manifest path: {path}", errors)
        require(isinstance(metadata, dict), f"invalid file metadata: {path}", errors)
        if isinstance(metadata, dict):
            require(
                set(metadata) == {"type", "sha256", "byte_length", "mode"},
                f"invalid file metadata fields: {path}",
                errors,
            )
            require(metadata.get("type") == "regular", f"non-regular file: {path}", errors)
            require(
                metadata.get("mode") == "0o444",
                f"unsafe file mode: {path}",
                errors,
            )
            require(
                isinstance(metadata.get("sha256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", metadata["sha256"]) is not None,
                f"invalid file digest: {path}",
                errors,
            )
            require(
                isinstance(metadata.get("byte_length"), int)
                and metadata["byte_length"] >= 0,
                f"invalid file length: {path}",
                errors,
            )
    return errors


def classify_change(
    rules: dict[str, Any],
    paths: list[str],
    change_kinds: list[str],
    repository: str | None = None,
) -> str:
    ranks = {risk: index for index, risk in enumerate(RISK_IDS)}
    floor = rules.get("repository_floors", {}).get(repository or "", "R0")
    if not paths:
        return rules["defaults"]["unknown_path"]
    effective = floor
    for path in paths:
        if not isinstance(path, str) or not path:
            return "R3"
        parsed = PurePosixPath(path)
        if (
            parsed.is_absolute()
            or "\\" in path
            or ".." in parsed.parts
            or "." in parsed.parts
        ):
            return "R3"
        matches = [
            rule["risk"]
            for rule in rules["path_rules"]
            if fnmatch.fnmatchcase(path, rule["pattern"])
        ]
        risk = max(matches, key=ranks.get) if matches else rules["defaults"]["unknown_path"]
        if ranks[risk] > ranks[effective]:
            effective = risk
    semantic = {
        rule["change_kind"]: rule["minimum_risk"]
        for rule in rules["semantic_rules"]
    }
    for change_kind in change_kinds:
        risk = semantic.get(
            change_kind, rules["defaults"]["unknown_change_kind"]
        )
        if ranks[risk] > ranks[effective]:
            effective = risk
    return effective


def classify_paths(
    rules: dict[str, Any], paths: list[str], repository: str | None = None
) -> str:
    return classify_change(rules, paths, [], repository)


def render_constitution(document: dict[str, Any]) -> str:
    metadata = document["metadata"]
    lines = [
        f"# Develop Constitution {metadata['revision']}",
        "",
        f"> Status: **{metadata['status'].upper()}**. This document grants no authority until independently ratified and activated.",
        "",
        "## Governing invariant",
        "",
        document["invariant"],
        "",
        "Autonomy is earned per capability, repository, and risk class. No system may promote itself.",
        "",
        "## Authority model",
        "",
        f"Lifecycle: `{' → '.join(document['lifecycle']['states'][:8])}`. Terminal states: {', '.join(f'`{item}`' for item in document['lifecycle']['terminal_states'])}.",
        "",
        "| Role | Principal kinds | Eligible capabilities | Absolute denials |",
        "|---|---|---|---|",
    ]
    for role_id, role in document["roles"].items():
        eligible = ", ".join(role["eligible_capabilities"]) or "none"
        denied = ", ".join(role["absolute_denials"]) or "none"
        lines.append(f"| `{role_id}` | {', '.join(role['principal_kinds'])} | {eligible} | {denied} |")
    lines.extend([
        "",
        "Role-separation constraints are normative in the machine source and apply at their declared scope.",
        "",
        "## Normative clauses",
        "",
        "| Clause | Requirement | Owner | Controls / tests |",
        "|---|---|---|---|",
    ])
    for clause_id, clause in document["clauses"].items():
        controls = ", ".join(clause["control_ids"])
        tests = ", ".join(clause["test_ids"])
        lines.append(f"| `{clause_id}` {clause['article']} | **{clause['strength']}** — {clause['text']} | `{clause['accountable_role']}` | {controls}; {tests} |")
    lines.extend([
        "",
        "Every v1 clause is unwaivable. A violation denies the action and demotes the affected scope to L0.",
        "",
        "## Risk classes",
        "",
        "| Risk | Meaning | Automated publication floor |",
        "|---|---|---|",
    ])
    for risk_id, risk in document["risk_classes"].items():
        floor = risk["minimum_maturity_for_automated_publication"] or "never"
        lines.append(f"| **{risk_id} — {risk['name']}** | {risk['description']} | `{floor}` |")
    lines.extend([
        "",
        "Candidate mutation and automated publication are separate ceilings. The stricter applicable rule wins.",
        "",
        "## Capability maturity",
        "",
        "| Level | Authority | Mutation ceiling | Non-human capability ceiling | Promotion floor |",
        "|---|---|---|---|---|",
    ])
    for level_id, level in document["maturity_levels"].items():
        capabilities = ", ".join(level["nonhuman_capability_ceiling"])
        floor = f"{level['minimum_governed_tasks']} tasks / {level['minimum_observation_days']} days / {level['promotion_approvals']} human approvals"
        lines.append(f"| **{level_id} — {level['name']}** | {level['authority']} | `{level['maximum_autonomous_mutation_risk']}` | {capabilities} | {floor} |")
    lines.extend([
        "",
        "Higher maturity retains every lower-level control. Promotions are scoped to an exact control-plane digest, repository, risk class, and capability.",
        "",
        "## Controls and adversarial evidence",
        "",
        "| Control | Owner | Enforcement point | Failure |",
        "|---|---|---|---|",
    ])
    for control_id, control in document["controls"].items():
        lines.append(f"| `{control_id}` | `{control['owner']}` | {control['enforcement_point']} | `{control['fail_mode']}` |")
    lines.extend(["", "| Test | Tier | Runner |", "|---|---|---|"])
    for test_id, test in document["tests"].items():
        lines.append(f"| `{test_id}` | `{test['tier']}` | `{test['runner']}` — {test['description']} |")
    amendment = document["amendment_policy"]
    exception = document["exception_policy"]
    lines.extend([
        "",
        "## Ratification",
        "",
        "The machine-readable source is `constitution/v1/constitution.json`; this rendering is informative. The previous active constitution governs amendments, and a candidate cannot approve or activate itself.",
        "",
        f"Permission expansion requires at least {amendment['minimum_human_approvals']} human approvals, independent security review, and a cooling period of {amendment['expansion_cooling_period_seconds']} seconds. Exceptions expire within {exception['maximum_ttl_seconds']} seconds and cannot waive an unwaivable clause.",
        "",
        "Candidate-controlled checks provide structural evidence only. Detached signatures, external verification, scoped control attestations, and a human installation ceremony are required for activation.",
        "",
    ])
    return "\n".join(lines)


def lint_repository(root: Path, schema_root: Path | None = None) -> list[str]:
    constitution = load_json(root / "constitution/v1/constitution.json")
    risk_rules = load_json(root / "constitution/v1/risk-rules.json")
    posture = load_json(root / "deployments/develop/posture.json")
    trust_root = load_json(root / "trust/root.json")
    schema_directory = (schema_root or root) / "schemas"
    actual_schema_names = {path.name for path in schema_directory.glob("*.json")}
    errors: list[str] = []
    require(
        actual_schema_names == EXPECTED_SCHEMAS,
        "schema set must match v1 exactly",
        errors,
    )
    schemas: dict[str, dict[str, Any]] = {}
    for path in sorted(schema_directory.glob("*.json")):
        schema = load_json(path)
        schemas[path.name] = schema
        errors.extend(
            f"{path.name}: {error}"
            for error in schema_definition_errors(schema)
        )
    instance_map = {
        "constitution-v1.schema.json": constitution,
        "risk-rules-v1.schema.json": risk_rules,
        "posture-v1.schema.json": posture,
        "trust-root-v1.schema.json": trust_root,
    }
    instance_errors: dict[str, list[str]] = {}
    for schema_name, instance in instance_map.items():
        if schema_name not in schemas:
            instance_errors[schema_name] = ["schema is missing"]
        else:
            instance_errors[schema_name] = schema_errors(
                instance, schemas[schema_name]
            )
        errors.extend(
            f"{schema_name}: {error}"
            for error in instance_errors[schema_name]
        )
    if not instance_errors["constitution-v1.schema.json"]:
        errors.extend(validate_constitution(constitution))
    if (
        not instance_errors["constitution-v1.schema.json"]
        and not instance_errors["risk-rules-v1.schema.json"]
    ):
        errors.extend(validate_risk_rules(risk_rules, constitution))
    if (
        not instance_errors["constitution-v1.schema.json"]
        and not instance_errors["posture-v1.schema.json"]
    ):
        errors.extend(validate_posture(posture, constitution))
    if (
        not instance_errors["constitution-v1.schema.json"]
        and not instance_errors["posture-v1.schema.json"]
        and not instance_errors["trust-root-v1.schema.json"]
    ):
        errors.extend(validate_trust_root(trust_root, constitution, posture))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(prog="constitutionctl")
    subparsers = parser.add_subparsers(dest="command", required=True)
    lint = subparsers.add_parser("lint")
    lint.add_argument("--root", type=Path, default=Path("."))
    lint.add_argument("--schema-root", type=Path)
    render = subparsers.add_parser("render")
    render.add_argument("--root", type=Path, default=Path("."))
    render.add_argument("--check", action="store_true")
    digest = subparsers.add_parser("digest")
    digest.add_argument("path", type=Path)
    classify = subparsers.add_parser("classify")
    classify.add_argument("--root", type=Path, default=Path("."))
    classify.add_argument("--repository")
    classify.add_argument("--change-kind", action="append", default=[])
    classify.add_argument("paths", nargs="+")
    args = parser.parse_args()

    try:
        if args.command == "lint":
            errors = lint_repository(
                args.root.resolve(),
                args.schema_root.resolve() if args.schema_root else None,
            )
            if errors:
                for error in errors:
                    print(f"error: {error}", file=sys.stderr)
                return 1
            print("constitution sources are valid")
            return 0
        if args.command == "render":
            root = args.root.resolve()
            constitution = load_json(root / "constitution/v1/constitution.json")
            expected = render_constitution(constitution)
            target = root / "CONSTITUTION.md"
            if args.check:
                if not target.exists() or target.read_text(encoding="utf-8") != expected:
                    print("error: CONSTITUTION.md is not the canonical rendering", file=sys.stderr)
                    return 1
                print("CONSTITUTION.md is current")
                return 0
            print(expected, end="")
            return 0
        if args.command == "digest":
            print(document_digest(load_json(args.path)))
            return 0
        if args.command == "classify":
            rules = load_json(args.root.resolve() / "constitution/v1/risk-rules.json")
            print(
                classify_change(
                    rules, args.paths, args.change_kind, args.repository
                )
            )
            return 0
    except ValidationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    raise AssertionError(args.command)


if __name__ == "__main__":
    sys.exit(main())
