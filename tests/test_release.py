from __future__ import annotations

import unittest

from factory.release import ReleasePolicyError, validate_release_operation


def release_result(*, production: bool) -> dict[str, object]:
    candidate = "a" * 40
    digest = "sha256:" + "b" * 64
    return {
        "status": "completed",
        "candidate_sha": candidate,
        "merge": {"performed": production, "merge_sha": candidate if production else None},
        "release": {"version": "0.1.0", "image_digest": digest},
        "staging": "deployed",
        "production": "deployed" if production else "not_started",
        "rollback": "not_needed" if production else "not_tested",
        "evidence_refs": ["evidence/gates.json", "evidence/staging.json"],
    }


class ReleaseValidationTests(unittest.TestCase):
    def test_staging_cannot_claim_merge_or_production(self) -> None:
        verification = validate_release_operation(release_result(production=False), stage="staging")
        self.assertEqual(verification.stage, "staging")

    def test_production_requires_exact_merge_binding(self) -> None:
        digest = "sha256:" + "b" * 64
        verification = validate_release_operation(
            release_result(production=True),
            stage="production",
            expected_staging_digest=digest,
        )
        self.assertEqual(verification.candidate_sha, "a" * 40)
        with self.assertRaises(ReleasePolicyError):
            validate_release_operation(
                {**release_result(production=True), "merge": {"performed": True, "merge_sha": "c" * 40}},
                stage="production",
            )

    def test_production_requires_accepted_staging_digest(self) -> None:
        with self.assertRaises(ReleasePolicyError):
            validate_release_operation(
                release_result(production=True),
                stage="production",
                expected_staging_digest="sha256:" + "c" * 64,
            )


if __name__ == "__main__":
    unittest.main()
