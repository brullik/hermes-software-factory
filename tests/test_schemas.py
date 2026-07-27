from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]


class SchemaTests(unittest.TestCase):
    def test_all_schemas_are_valid(self) -> None:
        schemas = list((ROOT / "schemas").glob("*.json"))
        self.assertGreaterEqual(len(schemas), 20)
        for path in schemas:
            with self.subTest(path=path.name):
                data = json.loads(path.read_text(encoding="utf-8"))
                Draft202012Validator.check_schema(data)

    def test_owner_action_example(self) -> None:
        schema = json.loads((ROOT / "schemas" / "owner-action.schema.json").read_text(encoding="utf-8"))
        artifact = json.loads((ROOT / "examples" / "owner-action.oauth.json").read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact))
        self.assertEqual(errors, [])

    def test_product_contract_template(self) -> None:
        schema = json.loads((ROOT / "schemas" / "product-contract.schema.json").read_text(encoding="utf-8"))
        artifact = json.loads((ROOT / "templates" / "product-contract.example.json").read_text(encoding="utf-8"))
        errors = list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(artifact))
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
