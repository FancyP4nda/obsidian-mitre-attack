from loguru import logger
from tqdm import tqdm
from stix2 import Filter
from stix2 import MemoryStore
import requests
import json

from .models import (MITREMatrix,
                     MITRETactic,
                     MITRETechnique,
                     MITREMitigation,
                     MITREGroup,
                     MITRESoftware)


MITRE_REPO_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"


class StixParser():
    """
    Get and parse ATT&CK STIX data.

    Domain should be 'enterprise-attack', 'mobile-attack', or 'ics-attack'.
    When version is omitted, MITRE's unversioned bundle is used. MITRE keeps
    that bundle aligned to the most recent release for the domain.
    """

    def __init__(self, repo_url, domain, version=None):
        self.domain = domain
        self.version = version
        self.source_url = None

        stix_json = self._load_stix_json(repo_url, domain, version)
        if 'objects' not in stix_json:
            logger.critical("The source provided does not contain a valid STIX bundle")
            exit(-1)

        self.collection_info = self._get_collection_info(stix_json)
        for collection_name, collection_version in self.collection_info:
            logger.info(f"Loaded {collection_name} {collection_version}")

        self.src = MemoryStore(stix_data=stix_json['objects'])

    def _load_stix_json(self, repo_url, domain, version):
        if repo_url != MITRE_REPO_URL:
            logger.warning("You have defined a different source for ATT&CK STIX data. The domain and version option will be ignored.")
            return self._load_custom_source(repo_url)

        if version:
            self.source_url = f"{repo_url}/{domain}/{domain}-{version}.json"
            logger.info(f"Downloading STIX data for domain {domain}, version {version}")
        else:
            self.source_url = f"{repo_url}/{domain}/{domain}.json"
            logger.info(f"Downloading latest STIX data for domain {domain}")

        return self._download_json(self.source_url)

    def _load_custom_source(self, source):
        self.source_url = source
        if source.startswith('http'):
            return self._download_json(source)

        try:
            with open(source, 'r') as fd:
                return json.loads(fd.read())
        except json.JSONDecodeError:
            logger.critical("You have provided an invalid JSON file")
            exit(-1)
        except FileNotFoundError:
            logger.critical("The file defined in the config.yml does not exist")
            exit(-1)

    def _download_json(self, url):
        response = requests.get(url, timeout=60)
        if response.status_code != 200:
            logger.critical(f"An error while reaching the remote source: {response.status_code} - {response.reason}")
            exit(-1)

        try:
            return response.json()
        except ValueError:
            logger.critical(f"The STIX data at {url} is not valid.")
            exit(-1)

    @staticmethod
    def _get_collection_info(stix_json):
        collections = []
        for obj in stix_json.get('objects', []):
            if obj.get('type') == 'x-mitre-collection':
                collections.append((obj.get('name', 'ATT&CK'), obj.get('x_mitre_version', 'unknown')))
        return collections

    @staticmethod
    def _is_truthy(value):
        return value is True or str(value).lower() == 'true'

    @classmethod
    def _is_active(cls, stix_obj):
        return not cls._is_truthy(stix_obj.get('revoked', False)) and not cls._is_truthy(stix_obj.get('x_mitre_deprecated', False))

    @staticmethod
    def _add_external_references(mitre_obj, stix_obj):
        for ext_ref in stix_obj.get('external_references', []):
            source_name = ext_ref.get('source_name', '')
            if source_name == 'mitre-attack':
                mitre_obj.id = ext_ref.get('external_id', mitre_obj.id)
            mitre_obj.references = (source_name, ext_ref.get('url', ''))

    def get_data(self, tactics=False,
                 techniques=False,
                 mitigations=False,
                 groups=False,
                 software=False,
                 matrices=False):

        self.tactics = list()
        self.techniques = list()
        self.mitigations = list()
        self.groups = list()
        self.software = list()
        self.matrices = list()
        if tactics:
            logger.info("Extracting Tactics...")
            self._get_tactics()
        if matrices:
            logger.info("Extracting Matrices...")
            self._get_matrices()
        if techniques:
            logger.info("Extracting Techniques...")
            self._get_techniques()
        if mitigations:
            logger.info("Extracting Mitigations...")
            self._get_mitigations()
        if groups:
            logger.info("Extracting Groups...")
            self._get_groups()
        if software:
            logger.info("Extracting Software...")
            self._get_software()

    def _get_tactics(self):
        """
        Get and parse tactics from STIX data
        """

        tactics_stix = self.src.query([Filter('type', '=', 'x-mitre-tactic')])
        self.tactics = list()

        for tactic in tqdm(tactics_stix):
            if not self._is_active(tactic):
                continue

            tactic_obj = MITRETactic(tactic['name'])
            tactic_obj.internal_id = tactic['id']
            tactic_obj.shortname = tactic.get('x_mitre_shortname', tactic['name'].lower().replace(' ', '-'))
            tactic_obj.description = tactic.get('description', '')
            self._add_external_references(tactic_obj, tactic)

            self.tactics.append(tactic_obj)

    def _get_matrices(self):
        """
        Get and parse active matrix definitions from STIX data.
        """

        matrices_stix = self.src.query([Filter('type', '=', 'x-mitre-matrix')])
        self.matrices = list()

        for matrix in tqdm(matrices_stix):
            if not self._is_active(matrix):
                continue

            matrix_obj = MITREMatrix(matrix['name'])
            matrix_obj.internal_id = matrix['id']
            matrix_obj.description = matrix.get('description', '')
            matrix_obj.tactic_refs = matrix.get('tactic_refs', [])
            self._add_external_references(matrix_obj, matrix)

            self.matrices.append(matrix_obj)

    def _get_techniques(self):
        """
        Get and parse techniques from STIX data
        """

        tech_stix = self.src.query([Filter('type', '=', 'attack-pattern')])
        self.techniques = list()

        for tech in tqdm(tech_stix):
            if not self._is_active(tech):
                continue

            technique_obj = MITRETechnique(tech['name'])
            technique_obj.internal_id = tech['id']
            self._add_external_references(technique_obj, tech)

            for kill_phase in tech.get('kill_chain_phases', []):
                technique_obj.kill_chain_phases = kill_phase

            technique_obj.is_subtechnique = tech.get('x_mitre_is_subtechnique', False)
            technique_obj.platforms = tech.get('x_mitre_platforms', [])
            technique_obj.permissions_required = tech.get('x_mitre_permissions_required', [])
            technique_obj.description = tech.get('description', '')

            self.techniques.append(technique_obj)

    def _get_mitigations(self):
        """
        Get and parse mitigations from STIX data
        """

        mitigations_stix = self.src.query([Filter('type', '=', 'course-of-action')])
        self.mitigations = list()

        for mitigation in tqdm(mitigations_stix):
            if not self._is_active(mitigation):
                continue

            mitigation_obj = MITREMitigation(mitigation['name'])
            mitigation_obj.internal_id = mitigation['id']
            mitigation_obj.description = mitigation.get('description', '')
            self._add_external_references(mitigation_obj, mitigation)

            mitigation_relationships = self.src.query([Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'mitigates'), Filter('source_ref', '=', mitigation_obj.internal_id)])

            for relationship in mitigation_relationships:
                if not self._is_active(relationship):
                    continue
                for technique in self.techniques:
                    refs = relationship.get('external_references', [])
                    for ext_ref in refs:
                        mitigation_obj.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                        technique.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                    if technique.internal_id == relationship['target_ref']:
                        mitigation_obj.mitigates = {'technique': technique, 'description': relationship.get('description', '')}
                        technique.mitigations = {'mitigation': mitigation_obj, 'description': relationship.get('description', '')}

            self.mitigations.append(mitigation_obj)

    def _get_groups(self):
        """
        Get and parse groups from STIX data
        """

        groups_stix = self.src.query([Filter('type', '=', 'intrusion-set')])
        self.groups = list()

        for group in tqdm(groups_stix):
            if not self._is_active(group):
                continue

            group_obj = MITREGroup(group['name'])
            group_obj.internal_id = group['id']
            self._add_external_references(group_obj, group)

            group_relationships = self.src.query([Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', group_obj.internal_id)])

            for relationship in group_relationships:
                if not self._is_active(relationship):
                    continue
                for technique in self.techniques:
                    if technique.internal_id == relationship['target_ref']:
                        refs = relationship.get('external_references', [])
                        for ext_ref in refs:
                            group_obj.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                            technique.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                        group_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '')}
                        technique.groups = {'group': group_obj, 'description': relationship.get('description', '')}
            group_obj.aliases = group.get('aliases', [])
            group_obj.description = group.get('description', '')

            self.groups.append(group_obj)

    def _get_software(self):
        """
        Get and parse software objects from STIX data
        """

        software_stix = self.src.query([Filter('type', '=', 'tool')]) + self.src.query([Filter('type', '=', 'malware')])
        self.software = list()

        for sw in tqdm(software_stix):
            if not self._is_active(sw):
                continue

            software_obj = MITRESoftware(sw['name'])
            software_obj.internal_id = sw['id']
            self._add_external_references(software_obj, sw)

            group_relationships = self.src.query([Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('target_ref', '=', software_obj.internal_id)])
            for relationship in group_relationships:
                if not self._is_active(relationship):
                    continue
                for group in self.groups:
                    if group.internal_id == relationship['source_ref']:
                        refs = relationship.get('external_references', [])
                        for ext_ref in refs:
                            software_obj.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                            group.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                        group.software_used = {'software': software_obj, 'description': relationship.get('description', '')}
                        software_obj.groups = {'group': group, 'description': relationship.get('description', '')}

            techniques_relationships = self.src.query([Filter('type', '=', 'relationship'), Filter('relationship_type', '=', 'uses'), Filter('source_ref', '=', software_obj.internal_id)])
            for relationship in techniques_relationships:
                if not self._is_active(relationship):
                    continue
                for technique in self.techniques:
                    if technique.internal_id == relationship['target_ref']:
                        refs = relationship.get('external_references', [])
                        for ext_ref in refs:
                            software_obj.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                            technique.references = (ext_ref.get('source_name', ''), ext_ref.get('url', ''))
                        software_obj.techniques_used = {'technique': technique, 'description': relationship.get('description', '')}
                        technique.software = {'software': software_obj, 'description': relationship.get('description', '')}

            software_obj.description = sw.get('description', '')
            self.software.append(software_obj)
