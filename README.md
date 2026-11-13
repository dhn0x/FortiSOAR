# FortiSOAR Community Connectors

Created and maintained by **dhaneshwar ([@dhn0x](https://github.com/dhn0x))**.

## CyberArk Privilege Cloud (ISPSS) — v1.0.2

A community FortiSOAR connector for CyberArk Privilege Cloud ISPSS and Privilege Cloud Standard. It provides 32 actions for privileged account discovery, credential retrieval and reconciliation, safe and membership administration, vault users and groups, and session recording retrieval. ISPSS supports separate Identity and API hosts and service-user OAuth2 authentication.

- [Installation and configuration](CONNECTORS/CYBERARK/README.md)
- [Detailed connector guide](CONNECTORS/CYBERARK/DOCUMENTATION.md)
- [All 32 actions and practical use cases](CONNECTORS/CYBERARK/ACTIONS_AND_USE_CASES.md)
- [Release notes](CONNECTORS/CYBERARK/release_notes.md)

## Installation

Download the `.tgz` package from [CONNECTORS/CYBERARK/dist](CONNECTORS/CYBERARK/dist) and import it through FortiSOAR **Content Hub → Manage → Add Connector**. Configure your tenant URLs, authentication and least-privilege permissions, keep certificate verification enabled, then run the connector health check. See the connector guide for the full configuration.

## Validation and sample playbooks

The connector requires the FortiSOAR connector SDK and an authorized CyberArk tenant for live validation. Local structural checks do not establish API compatibility or successful authentication. Bundled playbooks are legacy reference examples and require remapping before use; see the action guide.

This is a community project and is not an official CyberArk or Fortinet product. CyberArk and Fortinet names and logos belong to their respective owners.

## Claude Skill — FortiSOAR Playbook Engineering

A Claude skill for designing, building, reviewing, debugging and upgrading FortiSOAR playbooks to SOAR Framework standards. See [SKILLS/fortisoar-playbook-engineering](SKILLS/fortisoar-playbook-engineering/README.md).

## Author and license

Created by **dhaneshwar ([@dhn0x](https://github.com/dhn0x))**. Licensed under the [MIT License](LICENSE). Third-party names and logos remain the property of their respective owners.

## Integration walkthrough

See [step-by-step integration and examples for every action](CONNECTORS/CYBERARK/INTEGRATION_AND_ACTION_EXAMPLES.md).
