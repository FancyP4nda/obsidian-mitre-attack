from src.stix_parser import MITRE_REPO_URL, StixParser
from src.markdown_generator import MarkdownGenerator
from src.view import create_graph_json
from src.markdown_reader import MarkdownReader

from loguru import logger

import argparse
import os
import sys
import yaml
import re


SUPPORTED_DOMAINS = ('enterprise-attack', 'mobile-attack', 'ics-attack')


def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.yml')
    with open(config_path, 'r') as fd:
        return yaml.safe_load(fd)


def validate_domains(domains):
    invalid_domains = [domain for domain in domains if domain not in SUPPORTED_DOMAINS]
    if invalid_domains:
        logger.error(f"Unsupported domain(s): {', '.join(invalid_domains)}")
        exit(-1)
    return domains


def selected_build_domains(args, config):
    if args.all_domains:
        return list(SUPPORTED_DOMAINS)
    if args.domains:
        return validate_domains(args.domains)
    if args.domain:
        return validate_domains([args.domain])
    return validate_domains(config.get('domains') or ['enterprise-attack'])


def selected_single_domain(args):
    domain = args.domain or 'enterprise-attack'
    return validate_domains([domain])[0]


def ensure_output_dir(output):
    if not output:
        logger.error("You have not provided a valid output directory")
        exit(-1)

    if os.path.isdir(output):
        return output

    logger.warning("You have not provided an existing vault. Creating a new directory...")
    os.makedirs(output, exist_ok=True)
    return output


def build_domain(config, output_dir, domain):
    parser = StixParser(config.get('repository-url', MITRE_REPO_URL), domain, config.get('version'))
    logger.info(f"Extracting objects from STIX data for {domain}")
    parser.get_data(tactics=True, techniques=True, mitigations=True, groups=True, software=True, matrices=True)

    domain_output_dir = os.path.join(output_dir, domain)
    markdown_generator = MarkdownGenerator(
        domain_output_dir,
        parser.tactics,
        parser.techniques,
        parser.mitigations,
        parser.groups,
        parser.software,
        parser.matrices,
        domain=domain
    )

    object_types = config.get('mitre-object-types', {})
    if object_types.get('tactics', True):
        logger.info(f"Creating Tactic notes for {domain}")
        markdown_generator.create_tactic_notes()
    if object_types.get('techniques', True):
        logger.info(f"Creating Technique notes for {domain}")
        markdown_generator.create_technique_notes()
    if object_types.get('mitigations', True):
        logger.info(f"Creating Mitigation notes for {domain}")
        markdown_generator.create_mitigation_notes()
    if object_types.get('groups', True):
        logger.info(f"Creating Group notes for {domain}")
        markdown_generator.create_group_notes()
    if object_types.get('software', True):
        logger.info(f"Creating Software notes for {domain}")
        markdown_generator.create_software_notes()
    if object_types.get('matrices', True):
        logger.info(f"Creating Matrix canvases for {domain}")
        markdown_generator.create_matrix_canvases()


if __name__ == '__main__':
    logger.remove()
    logger.add(sys.stdout, colorize=True, format="[<level>{level}</level>] - <level>{message}</level>")

    parser = argparse.ArgumentParser(description='Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes')

    parser.add_argument('-d', '--domain', help="Single domain: 'enterprise-attack', 'mobile-attack' or 'ics-attack'")
    parser.add_argument('--domains', nargs='+', help="One or more domains to generate")
    parser.add_argument('--all-domains', help="Generate Enterprise, Mobile, and ICS ATT&CK", action="store_true")
    parser.add_argument('-o', '--output', help="Output directory in which the notes will be saved. It should be placed inside a Obsidian vault.")
    parser.add_argument('--generate-hyperlinks', help="Generate techniques hyperlinks in a markdown note file", action="store_true")
    parser.add_argument('--generate-matrix', help="Create ATT&CK matrix starting from a markdown note file", action="store_true")
    parser.add_argument('--path', help="Filepath to the markdown note file")

    args = parser.parse_args()
    config = load_config()

    if args.generate_hyperlinks:
        domain = selected_single_domain(args)
        if args.path:
            if os.path.isfile(args.path) and args.path.endswith('.md'):
                parser = StixParser(config.get('repository-url', MITRE_REPO_URL), domain, config.get('version'))
                logger.info("Extracting objects from STIX data")
                parser.get_data(techniques=True)
                markdown_reader = MarkdownReader(args.path)
                markdown_reader.create_hyperlinks(parser.techniques, domain=domain)
            else:
                logger.error("You have not provided a valid markdown file path")
        else:
            logger.error("Provide a file path")
    elif args.generate_matrix:
        domain = selected_single_domain(args)
        if args.path:
            parser = StixParser(config.get('repository-url', MITRE_REPO_URL), domain, config.get('version'))
            logger.info("Extracting objects from STIX data")
            parser.get_data(techniques=True, tactics=True, matrices=True)

            if os.path.isfile(args.path):
                if args.path.endswith('.md'):
                    logger.info("Reading the Markdown note")
                    markdown_reader = MarkdownReader(args.path)
                    found_techniques = markdown_reader.find_techniques()
                    canvas_path = re.sub('.md$', "", args.path)
                else:
                    logger.error("You must provide a path to a .md file")
                    exit(-1)
            else:
                logger.warning("You have not provided a valid markdown file path. The full matrix will be generated.")
                found_techniques = []
                canvas_path = args.path

            markdown_generator = MarkdownGenerator(techniques=parser.techniques, tactics=parser.tactics, matrices=parser.matrices)
            matrix = parser.matrices[0] if parser.matrices else None
            markdown_generator.create_canvas(canvas_path, found_techniques, matrix=matrix)
        else:
            logger.error("You must provide a valid file path")
            exit(-1)
    else:
        output_dir = ensure_output_dir(args.output)
        domains = selected_build_domains(args, config)
        for domain in domains:
            build_domain(config, output_dir, domain)

        create_graph_json(output_dir)
