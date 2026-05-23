import json
import os
import tempfile
import unittest
from unittest.mock import patch

from src.markdown_generator import MarkdownGenerator
from src.markdown_reader import MarkdownReader
from src.models import MITREMatrix, MITRETactic, MITRETechnique
from src.stix_parser import MITRE_REPO_URL, StixParser


class FakeResponse:
    status_code = 200
    reason = "OK"

    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


class FakeStore:
    def __init__(self, objects):
        self.objects = objects

    def query(self, filters):
        results = self.objects
        for filter_obj in filters:
            if filter_obj.op == '=':
                results = [obj for obj in results if obj.get(filter_obj.property) == filter_obj.value]
        return results


def tactic(name, external_id, internal_id, shortname):
    obj = MITRETactic(name)
    obj.id = external_id
    obj.internal_id = internal_id
    obj.shortname = shortname
    obj.description = f"{name} description"
    obj.references = ("mitre-attack", f"https://attack.mitre.org/tactics/{external_id}")
    return obj


def technique(name, external_id, phase_name, is_subtechnique=False):
    obj = MITRETechnique(name)
    obj.id = external_id
    obj.internal_id = f"attack-pattern--{external_id}"
    obj.description = f"{name} description"
    obj.is_subtechnique = is_subtechnique
    obj.platforms = ["Windows"]
    obj.permissions_required = []
    obj.kill_chain_phases = {
        "kill_chain_name": "mitre-attack",
        "phase_name": phase_name
    }
    obj.references = ("mitre-attack", f"https://attack.mitre.org/techniques/{external_id}")
    return obj


class LatestAllMatricesTest(unittest.TestCase):
    def test_latest_mode_uses_unversioned_domain_url(self):
        payload = {"objects": []}
        with patch("src.stix_parser.requests.get", return_value=FakeResponse(payload)) as requests_get:
            with patch("src.stix_parser.MemoryStore", side_effect=lambda stix_data: FakeStore(stix_data)):
                StixParser(MITRE_REPO_URL, "enterprise-attack")

        self.assertEqual(
            requests_get.call_args.args[0],
            f"{MITRE_REPO_URL}/enterprise-attack/enterprise-attack.json"
        )

    def test_versioned_mode_uses_explicit_release_url(self):
        payload = {"objects": []}
        with patch("src.stix_parser.requests.get", return_value=FakeResponse(payload)) as requests_get:
            with patch("src.stix_parser.MemoryStore", side_effect=lambda stix_data: FakeStore(stix_data)):
                StixParser(MITRE_REPO_URL, "enterprise-attack", "19.1")

        self.assertEqual(
            requests_get.call_args.args[0],
            f"{MITRE_REPO_URL}/enterprise-attack/enterprise-attack-19.1.json"
        )

    def test_parser_keeps_only_active_matrices_and_objects(self):
        objects = [
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--active",
                "name": "Initial Access",
                "description": "desc",
                "x_mitre_shortname": "initial-access",
                "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001", "url": "https://example.test/tactic"}],
            },
            {
                "type": "x-mitre-tactic",
                "id": "x-mitre-tactic--deprecated",
                "name": "Deprecated",
                "x_mitre_deprecated": True,
            },
            {
                "type": "x-mitre-matrix",
                "id": "x-mitre-matrix--active",
                "name": "Enterprise ATT&CK",
                "tactic_refs": ["x-mitre-tactic--active"],
                "external_references": [{"source_name": "mitre-attack", "external_id": "enterprise-attack", "url": "https://example.test/matrix"}],
            },
            {
                "type": "x-mitre-matrix",
                "id": "x-mitre-matrix--deprecated",
                "name": "Deprecated Matrix",
                "x_mitre_deprecated": True,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--active",
                "name": "Valid Technique",
                "description": "desc",
                "x_mitre_is_subtechnique": False,
                "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
                "external_references": [{"source_name": "mitre-attack", "external_id": "T1000", "url": "https://example.test/technique"}],
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--revoked",
                "name": "Revoked Technique",
                "revoked": True,
            },
        ]
        parser = StixParser.__new__(StixParser)
        parser.src = FakeStore(objects)

        parser.get_data(tactics=True, matrices=True, techniques=True)

        self.assertEqual([item.name for item in parser.tactics], ["Initial Access"])
        self.assertEqual([item.name for item in parser.matrices], ["Enterprise ATT&CK"])
        self.assertEqual([item.name for item in parser.techniques], ["Valid Technique"])

    def test_canvas_uses_matrix_tactic_order_and_domain_qualified_paths(self):
        initial = tactic("Initial Access", "TA0001", "x-mitre-tactic--initial", "initial-access")
        impact = tactic("Impact", "TA0040", "x-mitre-tactic--impact", "impact")
        matrix = MITREMatrix("Mobile ATT&CK")
        matrix.tactic_refs = ["x-mitre-tactic--initial", "x-mitre-tactic--impact"]
        tech = technique("Install Profile", "T1000", "initial-access")

        with tempfile.TemporaryDirectory() as temp_dir:
            domain_dir = os.path.join(temp_dir, "mobile-attack")
            generator = MarkdownGenerator(
                domain_dir,
                tactics=[impact, initial],
                techniques=[tech],
                matrices=[matrix],
                domain="mobile-attack"
            )
            generator.create_matrix_canvases()

            canvas_path = os.path.join(domain_dir, "matrices", "Mobile ATT&CK.canvas")
            with open(canvas_path, "r", encoding="utf-8") as fd:
                canvas = json.load(fd)

        groups = sorted([node for node in canvas["nodes"] if node["type"] == "group"], key=lambda node: node["x"])
        file_nodes = [node for node in canvas["nodes"] if node["type"] == "file"]

        self.assertEqual([group["label"] for group in groups], ["Initial Access", "Impact"])
        self.assertEqual(file_nodes[0]["file"], "mobile-attack/techniques/T1000 - Install Profile.md")

    def test_technique_notes_use_domain_qualified_links(self):
        initial = tactic("Initial Access", "TA0001", "x-mitre-tactic--initial", "initial-access")
        parent = technique("Parent Technique", "T1000", "initial-access")
        child = technique("Sub Technique", "T1000.001", "initial-access", is_subtechnique=True)

        with tempfile.TemporaryDirectory() as temp_dir:
            domain_dir = os.path.join(temp_dir, "enterprise-attack")
            generator = MarkdownGenerator(
                domain_dir,
                tactics=[initial],
                techniques=[parent, child],
                domain="enterprise-attack"
            )
            generator.create_technique_notes()

            note_path = os.path.join(domain_dir, "techniques", "T1000 - Parent Technique.md")
            with open(note_path, "r", encoding="utf-8") as fd:
                content = fd.read()

        self.assertIn("[[enterprise-attack/techniques/T1000.001 - Sub Technique.md\\|T1000.001]]", content)

    def test_hyperlink_generation_uses_domain_qualified_id_filenames(self):
        tech = technique("Parent Technique", "T1000", "initial-access")

        with tempfile.TemporaryDirectory() as temp_dir:
            note_path = os.path.join(temp_dir, "note.md")
            with open(note_path, "w", encoding="utf-8") as fd:
                fd.write("Uses T1000. End")

            reader = MarkdownReader(note_path)
            reader.create_hyperlinks([tech], domain="enterprise-attack")

            with open(note_path, "r", encoding="utf-8") as fd:
                content = fd.read()

        self.assertIn("[[enterprise-attack/techniques/T1000 - Parent Technique.md|T1000]]", content)


if __name__ == "__main__":
    unittest.main()
