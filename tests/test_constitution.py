import copy
import importlib.util
import json
import re
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "constitutionctl", ROOT / "tools/constitutionctl.py"
)
constitutionctl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(constitutionctl)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


class ConstitutionConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.constitution = constitutionctl.load_json(
            ROOT / "constitution/v1/constitution.json"
        )
        cls.risk_rules = constitutionctl.load_json(
            ROOT / "constitution/v1/risk-rules.json"
        )
        cls.posture = constitutionctl.load_json(
            ROOT / "deployments/develop/posture.json"
        )
        cls.trust_root = constitutionctl.load_json(ROOT / "trust/root.json")
        cls.schemas = {
            path.name: constitutionctl.load_json(path)
            for path in (ROOT / "schemas").glob("*.json")
        }

    def active_l0(self) -> tuple[dict, dict]:
        constitution = copy.deepcopy(self.constitution)
        constitution["metadata"]["status"] = "ratified"
        posture = copy.deepcopy(self.posture)
        posture.update(
            {
                "status": "active",
                "sequence": 1,
                "previous_posture_digest": DIGEST_A,
                "constitution_source_digest": constitutionctl.document_digest(
                    constitution
                ),
                "release_manifest_digest": DIGEST_B,
                "activation_envelope_digest": DIGEST_A,
                "control_attestation_set_digest": DIGEST_B,
                "effective_at": "2026-07-01T00:00:00Z",
            }
        )
        return constitution, posture

    def release_manifest(self) -> dict:
        def file(mode: str = "0o444") -> dict:
            return {
                "type": "regular",
                "sha256": "c" * 64,
                "byte_length": 1,
                "mode": mode,
            }

        return {
            "api_version": "develop.cenetex/v1",
            "kind": "ReleaseManifest",
            "workspace_id": "develop",
            "target_id": "develop-policy-store",
            "sequence": 1,
            "predecessor_manifest_digest": None,
            "revision": "1.0.0",
            "source_repository": "cenetex/develop-constitution",
            "source_commit": "a" * 40,
            "source_tree": "b" * 40,
            "constitution_document_digest": "sha256:" + "c" * 64,
            "canonicalization": "sorted-keys-utf8-no-whitespace-v1",
            "created_at": "2026-07-01T00:00:00Z",
            "files": {
                path: file()
                for path in constitutionctl.RELEASE_FILE_SET
            },
        }

    def test_repository_lints_and_render_is_canonical(self) -> None:
        self.assertEqual(constitutionctl.lint_repository(ROOT), [])
        self.assertEqual(
            (ROOT / "CONSTITUTION.md").read_text(),
            constitutionctl.render_constitution(self.constitution),
        )

    def test_duplicate_json_and_schema_mutations_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"kind":"A","kind":"B"}')
            with self.assertRaisesRegex(
                constitutionctl.ValidationError, "duplicate JSON key"
            ):
                constitutionctl.load_json(duplicate)
        candidate = copy.deepcopy(self.constitution)
        candidate["capabilities"]["repository.read"]["effect"] = []
        errors = constitutionctl.schema_errors(
            candidate, self.schemas["constitution-v1.schema.json"]
        )
        self.assertTrue(any("expected string" in error for error in errors))
        candidate["unexpected"] = True
        self.assertTrue(
            constitutionctl.schema_errors(
                candidate, self.schemas["constitution-v1.schema.json"]
            )
        )

    def test_schema_subset_rejects_unsupported_security_keywords(self) -> None:
        errors = constitutionctl.schema_definition_errors(
            {"type": "object", "unevaluatedProperties": False}
        )
        self.assertIn(
            "$: unsupported schema keyword unevaluatedProperties", errors
        )

    def test_risk_is_highest_of_repository_path_and_semantics(self) -> None:
        self.assertEqual(
            constitutionctl.classify_change(
                self.risk_rules, ["docs/guide.md"], [], None
            ),
            "R0",
        )
        for path in (
            "unknown.file",
            "../docs/readme.md",
            "/docs/readme.md",
            "docs/../src/auth.py",
            ".agents/governance.md",
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    constitutionctl.classify_change(
                        self.risk_rules, [path], [], None
                    ),
                    "R3",
                )
        for kind in ("symlink", "authentication", "authorization", "unknown"):
            with self.subTest(kind=kind):
                self.assertEqual(
                    constitutionctl.classify_change(
                        self.risk_rules, ["src/app.py"], [kind], None
                    ),
                    "R3",
                )
        self.assertEqual(
            constitutionctl.classify_change(
                self.risk_rules,
                ["docs/guide.md"],
                [],
                "cenetex/develop-constitution",
            ),
            "R3",
        )

    def test_worker_and_capability_sets_are_closed(self) -> None:
        self.assertEqual(
            set(self.constitution["capabilities"]),
            constitutionctl.EXPECTED_CAPABILITY_IDS,
        )
        for capability in constitutionctl.FORBIDDEN_WORKER_CAPABILITIES:
            self.assertFalse(
                constitutionctl.capability_eligible(
                    self.constitution, "worker", capability
                ),
                capability,
            )
        candidate = copy.deepcopy(self.constitution)
        candidate["capabilities"]["new.publish"] = copy.deepcopy(
            candidate["capabilities"]["github.push"]
        )
        self.assertIn(
            "v1 capability set must be exact",
            constitutionctl.validate_constitution(candidate),
        )

    def test_proposed_posture_grants_nothing_and_active_l0_is_read_only(self) -> None:
        now = datetime(2026, 7, 2, tzinfo=timezone.utc)
        proposed = constitutionctl.effective_capability_decision(
            self.constitution,
            self.posture,
            "control_plane",
            "service",
            "repository.read",
            "cenetex/example",
            "R1",
            DIGEST_A,
            now,
        )
        self.assertEqual(proposed, ("deny", "posture-inactive"))
        constitution, posture = self.active_l0()
        read = constitutionctl.effective_capability_decision(
            constitution,
            posture,
            "control_plane",
            "service",
            "repository.read",
            "cenetex/example",
            "R1",
            DIGEST_A,
            now,
        )
        self.assertEqual(read[0], "eligible")
        posture["effective_at"] = "2027-07-01T00:00:00Z"
        future = constitutionctl.effective_capability_decision(
            constitution,
            posture,
            "control_plane",
            "service",
            "repository.read",
            "cenetex/example",
            "R1",
            DIGEST_A,
            now,
        )
        self.assertEqual(future, ("deny", "posture-not-effective"))
        posture["effective_at"] = "2026-07-01T00:00:00Z"
        push = constitutionctl.effective_capability_decision(
            constitution,
            posture,
            "publication_broker",
            "service",
            "github.push",
            "cenetex/example",
            "R1",
            DIGEST_A,
            now,
        )
        self.assertEqual(push[0], "deny")

    def test_capability_grant_schema_rejects_bad_sha_time_and_extra_fields(self) -> None:
        grant = {
            "api_version": "develop.cenetex/v1",
            "kind": "CapabilityGrant",
            "grant_id": "grant-123456789012",
            "principal_id": "broker-1",
            "principal_kind": "service",
            "role": "publication_broker",
            "capability": "github.push",
            "task_id": "task-1",
            "repository": "cenetex/example",
            "risk_class": "R1",
            "constitution_source_digest": DIGEST_A,
            "release_manifest_digest": DIGEST_B,
            "control_plane_digest": DIGEST_A,
            "lease_attestation_digest": DIGEST_B,
            "control_attestation_digests": [],
            "issued_at": "not-a-time",
            "expires_at": "2026-07-01T00:00:00Z",
            "nonce": "1234567890abcdef",
            "bindings": {
                "task_id": "task-1",
                "repository": "cenetex/example",
                "branch": "agent/task-1",
                "head_sha": "not-a-sha",
                "expires_at": "2026-07-01T00:00:00Z",
            },
            "ambient_token": "forbidden",
        }
        errors = constitutionctl.schema_errors(
            grant, self.schemas["capability-grant-v1.schema.json"]
        )
        self.assertTrue(any("unknown property ambient_token" in e for e in errors))
        self.assertTrue(any("expected UTC date-time" in e for e in errors))

    def test_terminal_states_cannot_be_resurrected(self) -> None:
        for terminal in self.constitution["lifecycle"]["terminal_states"]:
            for target in self.constitution["lifecycle"]["states"]:
                self.assertFalse(
                    constitutionctl.transition_allowed(
                        self.constitution, terminal, target
                    )
                )
        self.assertTrue(
            constitutionctl.transition_allowed(
                self.constitution, "running", "verifying"
            )
        )

    def test_unsigned_approval_metadata_never_allows(self) -> None:
        subject = DIGEST_B
        approvals = [
            {
                "principal": "custodian-1",
                "principal_kind": "human",
                "head_sha": subject,
            },
            {
                "principal": "custodian-2",
                "principal_kind": "human",
                "head_sha": subject,
            },
        ]
        self.assertEqual(
            constitutionctl.approval_set_decision(subject, approvals, 2)[0],
            "review",
        )
        approvals[0]["head_sha"] = DIGEST_A
        self.assertEqual(
            constitutionctl.approval_set_decision(subject, approvals, 2),
            ("deny", "stale-sha"),
        )

    def test_amendment_uses_predecessor_external_classification_and_cooling(self) -> None:
        proposal = {
            "api_version": "develop.cenetex/v1",
            "kind": "AmendmentProposal",
            "issue": "https://github.com/cenetex/develop-constitution/issues/1",
            "requesting_principal": "proposer",
            "base_manifest_digest": DIGEST_A,
            "candidate_manifest_digest": DIGEST_B,
            "classification": "expansion",
            "classification_evidence_digest": DIGEST_A,
            "proposed_at": "2026-07-01T00:00:00Z",
            "activate_after": "2026-07-04T00:00:00Z",
            "authority_delta": "Adds one explicitly scoped capability.",
            "independent_security_review_digest": DIGEST_B,
            "threat_model": "A compromised worker may seek authority expansion.",
            "migration": "Deploy only after external ratification.",
            "rollback": "Restore the predecessor manifest.",
            "alternatives": ["Keep the current authority ceiling."],
        }
        self.assertEqual(
            constitutionctl.schema_errors(
                proposal, self.schemas["amendment-v1.schema.json"]
            ),
            [],
        )
        approvals = [
            {"principal": "c1", "principal_kind": "human", "head_sha": DIGEST_B},
            {"principal": "c2", "principal_kind": "human", "head_sha": DIGEST_B},
        ]
        now = datetime(2026, 7, 5, tzinfo=timezone.utc)
        self.assertEqual(
            constitutionctl.amendment_decision(
                self.constitution, DIGEST_A, proposal, approvals, now, None
            ),
            ("deny", "classification-unverified"),
        )
        decision = constitutionctl.amendment_decision(
            self.constitution,
            DIGEST_A,
            proposal,
            approvals,
            now,
            "expansion",
        )
        self.assertEqual(decision[0], "review")
        proposal["activate_after"] = "1970-01-01T00:00:00Z"
        self.assertEqual(
            constitutionctl.amendment_decision(
                self.constitution,
                DIGEST_A,
                proposal,
                approvals,
                now,
                "expansion",
            ),
            ("deny", "cooling-period"),
        )

    def test_unratified_or_unsigned_release_never_activates(self) -> None:
        now = datetime(2026, 7, 2, tzinfo=timezone.utc)
        self.assertEqual(
            constitutionctl.release_activation_decision(
                self.trust_root, {}, {}, None, 0, now
            ),
            ("deny", "trust-root-unratified"),
        )
        root = copy.deepcopy(self.trust_root)
        root.update(
            {
                "status": "active",
                "sequence": 1,
                "effective_at": "2026-07-01T00:00:00Z",
                "expires_at": "2026-08-01T00:00:00Z",
                "principals": [
                    {
                        "principal_id": "c1",
                        "key_id": "k1",
                        "algorithm": "ssh-ed25519",
                        "public_key": "x" * 32,
                        "status": "active",
                    },
                    {
                        "principal_id": "c2",
                        "key_id": "k2",
                        "algorithm": "ssh-ed25519",
                        "public_key": "y" * 32,
                        "status": "active",
                    },
                ],
            }
        )
        manifest = self.release_manifest()
        envelope = {
            "api_version": "develop.cenetex/v1",
            "kind": "SignatureEnvelope",
            "purpose": "constitution-release",
            "domain": "develop.cenetex/governance/v1",
            "workspace_id": "develop",
            "target_id": "develop-policy-store",
            "payload_digest": constitutionctl.document_digest(manifest),
            "trust_root_digest": constitutionctl.document_digest(root),
            "sequence": 1,
            "created_at": "2026-07-01T00:00:00Z",
            "expires_at": "2026-07-03T00:00:00Z",
            "nonce": "1234567890abcdef",
            "signatures": [
                {
                    "principal_id": "c1",
                    "key_id": "k1",
                    "algorithm": "ssh-ed25519",
                    "signature": "x" * 32,
                },
                {
                    "principal_id": "c2",
                    "key_id": "k2",
                    "algorithm": "ssh-ed25519",
                    "signature": "y" * 32,
                },
            ],
        }
        self.assertEqual(
            constitutionctl.release_activation_decision(
                root, envelope, manifest, None, 0, now
            )[0],
            "review",
        )

    def test_release_manifest_rejects_traversal_special_files_and_rollback(self) -> None:
        manifest = self.release_manifest()
        self.assertEqual(
            constitutionctl.schema_errors(
                manifest, self.schemas["release-manifest-v1.schema.json"]
            ),
            [],
        )
        manifest["files"]["docs/../../escape"] = {
            "type": "symlink",
            "sha256": "a" * 64,
            "byte_length": 1,
            "mode": "0o777",
        }
        errors = constitutionctl.release_manifest_errors(manifest, DIGEST_A, 4)
        schema_errors = constitutionctl.schema_errors(
            manifest, self.schemas["release-manifest-v1.schema.json"]
        )
        self.assertTrue(schema_errors)
        self.assertTrue(any("sequence" in error for error in errors))
        self.assertTrue(any("predecessor" in error for error in errors))
        self.assertTrue(any("unsafe manifest path" in error for error in errors))
        self.assertTrue(any("non-regular file" in error for error in errors))

    def test_scoped_promotion_cannot_self_promote(self) -> None:
        constitution, posture = self.active_l0()
        proposal = {
            "workspace_id": "develop",
            "previous_posture_digest": constitutionctl.document_digest(posture),
            "control_plane_digest": DIGEST_A,
            "requesting_component_digest": DIGEST_A,
        }
        self.assertEqual(
            constitutionctl.maturity_promotion_decision(
                constitution,
                posture,
                proposal,
                datetime(2026, 7, 5, tzinfo=timezone.utc),
            ),
            ("deny", "self-promotion"),
        )

    def test_controls_are_cumulative_and_platform_tests_are_not_unit_claims(self) -> None:
        previous = set()
        for level in self.constitution["maturity_levels"].values():
            current = set(level["required_controls"])
            self.assertLessEqual(previous, current)
            previous = current
        platform = [
            test
            for test in self.constitution["tests"].values()
            if test["tier"] == "platform"
        ]
        self.assertTrue(platform)
        self.assertTrue(
            all(test["runner"].startswith("external:") for test in platform)
        )

    def test_ci_is_candidate_only_pinned_and_least_privilege(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        uses = re.findall(r"uses: ([^\s]+)", workflow)
        self.assertTrue(uses)
        self.assertTrue(
            all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", item) for item in uses)
        )
        self.assertEqual(
            re.findall(r"(?m)^permissions:", workflow), ["permissions:"]
        )
        self.assertNotRegex(workflow, r"(?m)^[ \t]+permissions:")
        permission_block = re.search(
            r"(?m)^permissions:\n((?:[ \t]+[^\n]+\n)+)", workflow
        )
        self.assertIsNotNone(permission_block)
        self.assertEqual(permission_block.group(1), "  contents: read\n")
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("timeout-minutes: 10", workflow)
        self.assertIn("candidate-structural-check", workflow)
        for forbidden in ("pull_request_target", "write-all", "secrets."):
            self.assertNotIn(forbidden, workflow)

    def test_schema_inventory_is_exact_and_closed(self) -> None:
        self.assertEqual(set(self.schemas), constitutionctl.EXPECTED_SCHEMAS)
        for name, schema in self.schemas.items():
            self.assertFalse(schema["additionalProperties"], name)


if __name__ == "__main__":
    unittest.main()
