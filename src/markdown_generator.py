from jinja2 import Environment, FileSystemLoader
from . import ROOT

import json
import os
import re
import uuid


class MarkdownGenerator():

    def __init__(self, output_dir=None, tactics=None, techniques=None, mitigations=None,
                 groups=None, software=None, matrices=None, domain=None):
        if output_dir:
            self.output_dir = os.path.join(ROOT, output_dir)
        self.tactics = tactics or []
        self.techniques = techniques or []
        self.mitigations = mitigations or []
        self.groups = groups or []
        self.software = software or []
        self.matrices = matrices or []
        self.domain = domain
        self.environment = Environment(loader=FileSystemLoader(os.path.join(ROOT, "res/templates/")))
        self.environment.filters["parse_description"] = MarkdownGenerator.parse_description

    @staticmethod
    def parse_description(description, references=[]):
        description = description.replace('\n', '<br>')
        description = description.replace('</code>', '`')
        description = description.replace('<code>', '`')

        for ref in references:
            description = re.sub(fr'\(Citation: {ref["source_name"]}\)', f'[^{ref["id"]}] ', description)
        return description

    @staticmethod
    def _mitre_attack_url(mitre_object):
        for ref in mitre_object.references:
            if ref[0] == 'mitre-attack':
                return ref[1]
        return ''

    def _note_path(self, category, mitre_object):
        path_parts = [category, self._filename(mitre_object)]
        if self.domain:
            path_parts.insert(0, self.domain)
        return "/".join(path_parts)

    @staticmethod
    def _filename(mitre_object):
        if mitre_object.id:
            return f"{mitre_object.id} - {mitre_object.name}.md"
        return f"{mitre_object.name}.md"

    def _link_item(self, category, mitre_object, description=''):
        return {
            "name": mitre_object.name,
            "id": mitre_object.id,
            "link": self._note_path(category, mitre_object),
            "description": description
        }

    def _references(self, mitre_object):
        footnote_id = 1
        references = {}
        for ref in mitre_object.references:
            if ref[0] == 'mitre-attack':
                continue
            source_name = ref[0]
            if source_name not in references:
                references[source_name] = {
                    'id': footnote_id,
                    'url': ref[1]
                }
                footnote_id += 1
        return [{"id": value["id"],
                 "source_name": source_name,
                 "url": value["url"]} for source_name, value in references.items()]

    def _ensure_dir(self, *parts):
        path = os.path.join(self.output_dir, *parts)
        os.makedirs(path, exist_ok=True)
        return path

    def create_tactic_notes(self):
        template = self.environment.get_template("tactic.md")
        tactics_dir = self._ensure_dir("tactics")

        for tactic in self.tactics:
            content = template.render(
                    aliases=[tactic.id],
                    mitre_attack=self._mitre_attack_url(tactic),
                    title=tactic.id,
                    description=tactic.description
            )
            tactic_file = os.path.join(tactics_dir, self._filename(tactic))

            with open(tactic_file, 'w', encoding="utf-8") as fd:
                fd.write(content)

    def create_technique_notes(self):
        template = self.environment.get_template("technique.md")
        techniques_dir = self._ensure_dir("techniques")

        for technique in self.techniques:
            references = self._references(technique)
            tactics = []
            for kill_chain in technique.kill_chain_phases:
                if kill_chain["kill_chain_name"] in ('mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack'):
                    tactics += [t.name for t in self.tactics if t.shortname == kill_chain["phase_name"].lower()]

            content = template.render(
                    aliases=[technique.id],
                    mitre_attack=self._mitre_attack_url(technique),
                    tactics=tactics,
                    platforms=technique.platforms,
                    permissions_required=technique.permissions_required,
                    title=technique.id,
                    description=technique.description,
                    procedures=[self._link_item("software", sw["software"], sw["description"]) for sw in technique.software] +
                               [self._link_item("groups", g["group"], g["description"]) for g in technique.groups],
                    mitigations=[self._link_item("mitigations", m["mitigation"], m["description"]) for m in technique.mitigations],
                    subtechniques=[self._link_item("techniques", subt) for subt in self.techniques if self._is_subtechnique_of(technique, subt)],
                    references=references
            )

            technique_file = os.path.join(techniques_dir, self._filename(technique))

            with open(technique_file, 'w', encoding="utf-8") as fd:
                fd.write(content)

    def create_mitigation_notes(self):
        template = self.environment.get_template("mitigation.md")
        mitigations_dir = self._ensure_dir("mitigations")

        for mitigation in self.mitigations:
            mitigation_file = os.path.join(mitigations_dir, self._filename(mitigation))
            references = self._references(mitigation)

            content = template.render(
                    aliases=[mitigation.id],
                    mitre_attack=self._mitre_attack_url(mitigation),
                    title=mitigation.id,
                    description=mitigation.description,
                    techniques=[self._link_item("techniques", t["technique"], t["description"]) for t in mitigation.mitigates],
                    references=references
            )
            with open(mitigation_file, 'w', encoding="utf-8") as fd:
                fd.write(content)

    def create_group_notes(self):
        template = self.environment.get_template("group.md")
        groups_dir = self._ensure_dir("groups")

        for group in self.groups:
            group_file = os.path.join(groups_dir, self._filename(group))
            references = self._references(group)

            content = template.render(
                    aliases=group.aliases,
                    mitre_attack=self._mitre_attack_url(group),
                    title=group.id,
                    description=group.description,
                    techniques=[self._link_item("techniques", t["technique"], t["description"]) for t in group.techniques_used],
                    software=[self._link_item("software", s["software"], s["description"]) for s in group.software_used],
                    references=references
            )
            with open(group_file, 'w', encoding="utf-8") as fd:
                fd.write(content)

    def create_software_notes(self):
        template = self.environment.get_template("software.md")
        software_dir = self._ensure_dir("software")

        for software in self.software:
            references = self._references(software)
            techniques_used = [self._link_item("techniques", tech["technique"], tech["description"]) for tech in software.techniques_used]
            groups = [self._link_item("groups", group["group"], group["description"]) for group in software.groups]

            content = template.render(
                    aliases=[software.id],
                    mitre_attack=self._mitre_attack_url(software),
                    title=software.id,
                    description=software.description,
                    techniques=techniques_used,
                    groups=groups,
                    references=references
            )
            software_file = os.path.join(software_dir, self._filename(software))

            with open(software_file, 'w', encoding="utf-8") as fd:
                fd.write(content)

    def create_matrix_canvases(self):
        matrices_dir = self._ensure_dir("matrices")
        for matrix in self.matrices:
            self.create_canvas(os.path.join(matrices_dir, matrix.name), matrix=matrix)

    def create_canvas(self, canvas_name, filtered_techniques=None, matrix=None):
        filtered_techniques = filtered_techniques or []
        canvas = {
                "nodes": [],
                "edges": []
            }

        ordered_tactics = self._ordered_tactics(matrix)
        columns = {tactic.name: index * 500 for index, tactic in enumerate(ordered_tactics)}
        rows = {tactic.name: 50 for tactic in ordered_tactics}
        height = 144
        max_height = 50

        parent_techniques = [technique for technique in self.techniques if not technique.is_subtechnique]
        for tactic in ordered_tactics:
            for technique in parent_techniques:
                if not self._include_technique(technique, filtered_techniques):
                    continue
                if not self._technique_matches_tactic(technique, tactic):
                    continue

                x = columns[tactic.name] + 20
                y = rows[tactic.name]
                technique_node = {
                    "type": "file",
                    "file": self._note_path("techniques", technique),
                    "id": uuid.uuid4().hex,
                    "x": x,
                    "y": y,
                    "width": 450,
                    "height": height
                }
                canvas["nodes"].append(technique_node)
                y = y + height + 20

                subtechniques = [subt for subt in self.techniques if self._is_subtechnique_of(technique, subt)]
                for subt in subtechniques:
                    if filtered_techniques and subt.id not in filtered_techniques:
                        continue
                    subtech_node = {
                        "type": "file",
                        "file": self._note_path("techniques", subt),
                        "id": uuid.uuid4().hex,
                        "x": x + 50,
                        "y": y,
                        "width": 400,
                        "height": height
                    }
                    y = y + height + 20
                    canvas["nodes"].append(subtech_node)

                rows[tactic.name] = y
                if y > max_height:
                    max_height = y

        for tactic in ordered_tactics:
            container_node = {
                "type": "group",
                "label": f"{tactic.name}",
                "id": uuid.uuid4().hex,
                "x": columns[tactic.name],
                "y": 0,
                "width": 500,
                "height": max_height + 20
            }
            canvas["nodes"].append(container_node)

        canvas_path = f"{canvas_name}.canvas"
        os.makedirs(os.path.dirname(canvas_path) or ".", exist_ok=True)
        with open(canvas_path, 'w', encoding="utf-8") as fd:
            fd.write(json.dumps(canvas, indent=2))

    def _ordered_tactics(self, matrix):
        if matrix:
            tactics_by_id = {tactic.internal_id: tactic for tactic in self.tactics}
            return [tactics_by_id[tactic_ref] for tactic_ref in matrix.tactic_refs if tactic_ref in tactics_by_id]
        return self.tactics

    @staticmethod
    def _is_subtechnique_of(parent, candidate):
        return candidate.is_subtechnique and candidate.id.startswith(f"{parent.id}.")

    @staticmethod
    def _include_technique(technique, filtered_techniques):
        if not filtered_techniques:
            return True
        return technique.id in filtered_techniques

    @staticmethod
    def _technique_matches_tactic(technique, tactic):
        tactic_keys = {tactic.shortname, tactic.name.lower().replace(' ', '-')}
        for kill_chain in technique.kill_chain_phases:
            if kill_chain["kill_chain_name"] in ('mitre-attack', 'mitre-mobile-attack', 'mitre-ics-attack'):
                if kill_chain["phase_name"].lower() in tactic_keys:
                    return True
        return False
