# obsidian-mitre-attack

[![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-e2231a?style=for-the-badge)](https://attack.mitre.org/)
[![STIX 2.1](https://img.shields.io/badge/STIX-2.1-4b5563?style=for-the-badge)](https://oasis-open.github.io/cti-documentation/)
[![Obsidian](https://img.shields.io/badge/Obsidian-ready-7C3AED?style=for-the-badge&logo=obsidian&logoColor=white)](https://obsidian.md/)
[![Tests](https://img.shields.io/badge/tests-unittest-16A34A?style=for-the-badge)](#testing)
[![License: GPLv3](https://img.shields.io/badge/license-GPLv3-111827?style=for-the-badge)](LICENSE)

`obsidian-mitre-attack` generates an Obsidian-friendly MITRE ATT&CK reference vault from the official MITRE ATT&CK STIX 2.1 data.

The default configuration pulls MITRE's latest unversioned ATT&CK bundles and builds separate Enterprise, Mobile, and ICS reference folders, including active ATT&CK matrices as Obsidian canvas files.

## Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Attribution](#attribution)
- [Contributing](#contributing)
- [License](#license)

## About

This project downloads ATT&CK data from [`mitre-attack/attack-stix-data`](https://github.com/mitre-attack/attack-stix-data), parses the STIX objects, and writes Markdown notes that are easy to browse in Obsidian.

Generated notes include tactics, techniques, mitigations, groups, software, and matrix canvases. Links are written as Obsidian wiki links, and note filenames are prefixed with ATT&CK IDs to avoid collisions when MITRE uses the same name for multiple objects.

By default, `version` is left empty in `config.yml`. That makes the script use MITRE's unversioned domain JSON files, which track the latest published ATT&CK release.

## Features

- Pulls latest MITRE ATT&CK STIX 2.1 data by default.
- Supports Enterprise ATT&CK, Mobile ATT&CK, and ATT&CK for ICS.
- Generates per-domain folders to keep object names and links unambiguous.
- Creates Markdown notes for tactics, techniques, mitigations, groups, and software.
- Creates one Obsidian `.canvas` matrix file for each active official matrix.
- Builds matrix columns dynamically from MITRE `x-mitre-matrix.tactic_refs`.
- Uses ATT&CK ID-prefixed filenames, such as `T1059 - Command and Scripting Interpreter.md`.
- Supports hyperlinking ATT&CK technique IDs inside existing Markdown notes.

## Installation

1. Clone this repository:

```bash
git clone https://github.com/FancyP4nda/obsidian-mitre-attack.git
cd obsidian-mitre-attack
```

2. Create and activate a Python virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Generate the configured domains into an Obsidian vault or output folder:

```bash
python run.py -o /path/to/obsidian-vault
```

The default `config.yml` generates:

- `enterprise-attack/`
- `mobile-attack/`
- `ics-attack/`

Each domain folder contains:

```text
tactics/
techniques/
mitigations/
groups/
software/
matrices/
```

Generate every supported domain explicitly:

```bash
python run.py -o /path/to/obsidian-vault --all-domains
```

Generate only selected domains:

```bash
python run.py -o /path/to/obsidian-vault --domains enterprise-attack ics-attack
python run.py -o /path/to/obsidian-vault --domain mobile-attack
```

Generate a standalone matrix canvas for one domain:

```bash
python run.py --generate-matrix --domain enterprise-attack --path /path/to/Enterprise-Matrix
```

Generate a matrix canvas from techniques found in an existing Markdown note:

```bash
python run.py --generate-matrix --domain enterprise-attack --path /path/to/note.md
```

Convert ATT&CK technique IDs in an existing Markdown note into Obsidian links:

```bash
python run.py --generate-hyperlinks --domain enterprise-attack --path /path/to/note.md
```

### Configuration

`config.yml` controls source data, domains, and object types:

```yaml
repository-url: https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master
version:
domains:
  - enterprise-attack
  - mobile-attack
  - ics-attack
mitre-object-types:
  tactics: true
  techniques: true
  mitigations: true
  groups: true
  software: true
  matrices: true
```

Key options:

- `repository-url`: Base URL for MITRE ATT&CK STIX data.
- `version`: Leave empty for latest. Set a version, such as `19.1`, to pull a specific release.
- `domains`: Domain list used when no CLI domain override is provided.
- `mitre-object-types`: Enables or disables categories of generated notes.

### CLI Reference

```text
usage: run.py [-h] [-d DOMAIN] [--domains DOMAINS [DOMAINS ...]]
              [--all-domains] [-o OUTPUT] [--generate-hyperlinks]
              [--generate-matrix] [--path PATH]

Download MITRE ATT&CK STIX data and parse it to Obsidian markdown notes

options:
  -h, --help            show this help message and exit
  -d, --domain DOMAIN   Single domain: 'enterprise-attack', 'mobile-attack' or
                        'ics-attack'
  --domains DOMAINS [DOMAINS ...]
                        One or more domains to generate
  --all-domains         Generate Enterprise, Mobile, and ICS ATT&CK
  -o, --output OUTPUT   Output directory in which the notes will be saved. It
                        should be placed inside an Obsidian vault.
  --generate-hyperlinks
                        Generate techniques hyperlinks in a markdown note file
  --generate-matrix     Create ATT&CK matrix starting from a markdown note
                        file
  --path PATH           Filepath to the markdown note file
```

## Project Structure

```text
.
|-- config.yml
|-- requirements.txt
|-- run.py
|-- res/
|   |-- graph.json
|   `-- templates/
|       |-- group.md
|       |-- mitigation.md
|       |-- software.md
|       |-- tactic.md
|       `-- technique.md
|-- src/
|   |-- markdown_generator.py
|   |-- markdown_reader.py
|   |-- models.py
|   |-- stix_parser.py
|   `-- view.py
`-- tests/
    `-- test_latest_all_matrices.py
```

## Testing

Run the unit tests:

```bash
python -m unittest discover -v
```

Run a live smoke generation against MITRE's current latest data:

```bash
rm -rf /tmp/mitre-attack-vault
python run.py -o /tmp/mitre-attack-vault --all-domains
```

## Attribution

This fork is based on [`vincenzocaputo/obsidian-mitre-attack`](https://github.com/vincenzocaputo/obsidian-mitre-attack) and remains licensed under GPLv3.

Generated ATT&CK content is based on MITRE ATT&CK data. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation. When copying or distributing generated ATT&CK content, include MITRE's notice:

```text
© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
```

Use of MITRE ATT&CK does not imply endorsement by MITRE.

## Contributing

Issues and pull requests are welcome. Before opening a PR, run:

```bash
python -m unittest discover -v
python -m py_compile run.py src/*.py tests/*.py
```

## License

This project is licensed under the GNU General Public License v3.0. See [`LICENSE`](LICENSE) for details.
