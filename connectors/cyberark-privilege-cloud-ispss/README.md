# CyberArk Privilege Cloud (ISPSS) — FortiSOAR Connector

A FortiSOAR connector for **CyberArk Privilege Cloud**, built to work with the
**Identity Security Platform Shared Services (ISPSS)** deployment as well as the
legacy **Privilege Cloud Standard** deployment. It uses the CyberArk Privilege
Cloud REST API (Gen 2).

ISPSS tenants authenticate through CyberArk Identity (the
`/oauth2/platformtoken` endpoint) and serve the PVWA API from a separate host,
which the stock handling does not always account for. This connector adds
explicit Identity / API host fields and an OAuth2 service-user auth type to
cover that case.

- **Connector name:** `cyberark-privilege-cloud-ispss`
- **Version:** 1.0.2
- **Category:** Vault / PAM

## Supported deployments

| Deployment | Portal example | Identity host | API host |
|---|---|---|---|
| ISPSS | `https://acme.cyberark.cloud` | `https://<tenant-id>.id.cyberark.cloud` | `https://<subdomain>.privilegecloud.cyberark.cloud` |
| Standard | `https://acme.privilegecloud.cyberark.com` | n/a (same host) | `https://<subdomain>.privilegecloud.cyberark.com` |

The platform is auto-detected from the Server URL: a `.cyberark.cloud` host is
treated as ISPSS, a `.privilegecloud.cyberark.com` host as Standard.

## Authentication

| Type | Use | How it authenticates |
|---|---|---|
| `ServiceUser` | Recommended for automation (ISPSS) | OAuth2 client credentials via `/oauth2/platformtoken`. `client_id` / `client_secret` are the Identity **service user** login name and password. |
| `CyberArk` / `LDAP` / `RADIUS` | Interactive Identity logon | Username + password. An account with an MFA policy cannot complete non-interactive logon. |

For a service user, create it in CyberArk Identity (Identity Administration →
Core Services → Users) with **"Is OAuth confidential client"** enabled and **no
MFA policy** applied.

## Configuration

| Field | Required | Notes |
|---|---|---|
| Server URL | Yes | ISPSS: `https://<subdomain>.cyberark.cloud`. Standard: `https://<subdomain>.privilegecloud.cyberark.com`. |
| Identity Tenant URL | No | ISPSS only. Set when the Identity tenant ID differs from the portal subdomain. Blank → auto-derive `<subdomain>.id.cyberark.cloud`. |
| Privilege Cloud API URL | No | Set only if the API host differs from the derived `<subdomain>.privilegecloud.cyberark.cloud`. |
| Authentication Type | Yes | `ServiceUser`, `CyberArk`, `LDAP`, or `RADIUS`. |
| Username / Client ID | Yes | Service user login name (ServiceUser), or account username. |
| Password / Client Secret | Yes | Service user password (ServiceUser), or account password. |
| Concurrent Session | No | Allow concurrent CyberArk sessions. |
| Verify SSL | No | Validate the server certificate. |

### Finding the ISPSS Identity Tenant URL

On many ISPSS tenants the Identity tenant ID is **not** the portal subdomain
(e.g. portal `acme.cyberark.cloud` but Identity host
`abc1234.id.cyberark.cloud`). To find the real one:

1. Open the portal URL in a browser and read the host it redirects to
   (`https://<tenant-id>.id.cyberark.cloud`); or
2. Ask CyberArk support for the Identity tenant URL and the Privilege Cloud API
   URL.

Then set **Identity Tenant URL** to that host. Both hosts must be reachable on
443 from the FortiSOAR node or agent running the connector.

## Least privilege

Grant the service user only the permissions the playbooks use. For credential
retrieval, **List Accounts** + **Retrieve Accounts** on the relevant safe(s) is
sufficient. Safe / user / member management operations require additional
vault-level authorizations; do not grant them unless they are needed.

## Operations

**Accounts**
- Get Accounts, Get Account Details, Retrieve Account Password, Reconcile Credentials

**Safes**
- List Safes, Get Safe Details, Add Safe, Update Safe, Delete Safe

**Safe Members**
- List Safe Members, Add Safe Member, Update Safe Member, Delete Safe Member

**Account Groups**
- Get Safe Account Groups, Get Account Group Members, Add Account Group Member, Delete Account Group Member

**Users**
- Get Users, Get User Details, Add User, Update User, Delete User, Reset User Password, Activate User

**User Groups**
- Get Groups, Add User to Group

**Session Recordings**
- Get Recordings, Get Recording Details, Play Recording

**Credentials (vault-style)**
- Get Credentials, Get Credentials Details, Get Credential

## Installation

Import the connector tarball into FortiSOAR via **Content Hub → Manage →
Add Connector**, then configure a Vault / connector configuration with the
fields above and run the health check.

## Disclaimer

This is a community connector, not an official CyberArk or Fortinet product.
Test in a non-production environment before deploying.

## Author and license

Created by **dhaneshwar ([@dhn0x](https://github.com/dhn0x))**. Licensed under the [MIT License](LICENSE). Third-party names and logos remain the property of their respective owners.
