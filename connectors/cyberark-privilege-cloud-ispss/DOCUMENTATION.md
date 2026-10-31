# CyberArk Privilege Cloud (ISPSS) — FortiSOAR Connector Guide

The CyberArk Privilege Cloud (ISPSS) connector lets FortiSOAR manage privileged
accounts, safes, safe members, account groups, vault users, user groups, and
session recordings, and retrieve credentials, using the CyberArk Privilege Cloud
REST API (Gen 2). It supports both the Identity Security Platform Shared
Services (ISPSS) deployment and the legacy Privilege Cloud Standard deployment.

- **Connector name:** `cyberark-privilege-cloud-ispss`
- **Version:** 1.0.2
- **Category:** Vault / PAM

---

## 1. Compatibility

| Item | Requirement |
|---|---|
| FortiSOAR | A release that supports custom connectors and the Password Vault integration. |
| CyberArk | Privilege Cloud (ISPSS) or Privilege Cloud Standard, REST API Gen 2. |
| Network | The FortiSOAR node or agent running the connector must reach the Identity host and the Privilege Cloud API host on TCP 443. |

The platform is auto-detected from the **Server URL**: a `*.cyberark.cloud` host
is treated as ISPSS; a `*.privilegecloud.cyberark.com` host as Standard.

---

## 2. Prerequisites

### 2.1 FortiSOAR side
- Outbound HTTPS (443) from the executing node/agent to **both** the Identity
  host (`<tenant-id>.id.cyberark.cloud`) and the API host
  (`<subdomain>.privilegecloud.cyberark.cloud`). If the connector runs on a
  tenant agent rather than the main node, the **agent** needs that egress.

### 2.2 CyberArk side — ISPSS with a service user (recommended)
1. In **Identity Administration → Core Services → Users**, create a service user.
2. Enable **"Is OAuth confidential client"** on that user.
3. Apply **no MFA / authentication policy** to the user. A user with an MFA
   policy cannot complete the non-interactive client-credentials flow.
4. Add the service user to the role that grants access to the Privilege Cloud
   APIs (**Core Services → Roles**).
5. Add the service user as a **Safe Member** on the relevant safe(s) with only
   the permissions the playbooks need (see section 6).

For this auth type, the connector's **Username / Client ID** is the service
user's login name and the **Password / Client Secret** is the service user's
password. There is no separate API key.

### 2.3 CyberArk side — Standard or interactive Identity
Use a vault/Identity account with the appropriate authentication method
(`CyberArk`, `LDAP`, or `RADIUS`) and the safe/vault permissions required by the
operations in use. The same MFA limitation applies to interactive logon.

---

## 3. Finding the ISPSS Identity Tenant URL

On many ISPSS tenants the Identity tenant ID is **not** the same as the portal
subdomain — for example, portal `acme.cyberark.cloud` but Identity host
`abc1234.id.cyberark.cloud`. If the Identity host is wrong, authentication fails
with a DNS / "name or service not known" error before credentials are checked.

To find the real Identity host:
1. Open the portal URL in a browser and read the host it redirects to
   (`https://<tenant-id>.id.cyberark.cloud`); or
2. Ask CyberArk support (or your CyberArk admin) for the Identity tenant URL and
   the Privilege Cloud API URL.

Enter that host in the **Identity Tenant URL** field. Leave the URL fields blank
only if the Identity/API hosts genuinely follow the `<subdomain>` pattern.

---

## 4. Installation

Import the connector tarball in FortiSOAR via **Content Hub → Manage → Add
Connector**, upload the `.tgz`, then create a configuration as in section 5 and
run **Health Check**.

---

## 5. Configuration parameters

| Parameter | Required | Description |
|---|---|---|
| Server URL | Yes | ISPSS: `https://<subdomain>.cyberark.cloud`. Standard: `https://<subdomain>.privilegecloud.cyberark.com`. |
| Identity Tenant URL | No | ISPSS only. Full Identity host serving `/oauth2/platformtoken`. Set when the Identity tenant ID differs from the portal subdomain. Blank → auto-derive `https://<subdomain>.id.cyberark.cloud`. |
| Privilege Cloud API URL | No | Full PVWA API base URL. Set only if the API host differs from `https://<subdomain>.privilegecloud.cyberark.cloud`. Blank → auto-derive. |
| Authentication Type | Yes | `ServiceUser`, `CyberArk`, `LDAP`, or `RADIUS`. |
| Username / Client ID | Yes | Service user login name (ServiceUser) or account username. |
| Password / Client Secret | Yes | Service user password (ServiceUser) or account password. Write-only. |
| Concurrent Session | No | Allow concurrent CyberArk sessions. |
| Use As Vault | No | Expose the connector as a FortiSOAR credential vault. |
| Verify SSL | No | Validate the server TLS certificate. |

### Authentication types

| Type | Endpoint used | Credential meaning |
|---|---|---|
| `ServiceUser` | `/oauth2/platformtoken` (OAuth2 client credentials) | Client ID / Secret = service user login name / password. |
| `CyberArk` / `LDAP` / `RADIUS` | Identity interactive logon (`/Security/StartAuthentication`) | Username / password of the account. |

---

## 6. Least-privilege permission map

Grant only what the playbooks use. Mapping of operation groups to the CyberArk
permissions they require:

| Operation group | CyberArk permission required |
|---|---|
| List/Get accounts, safes, members, account groups, recordings | Safe membership with **List Accounts** / view members; recordings need access to the recordings safe. |
| Retrieve Account Password, Get Credential | **Retrieve Accounts** on the safe. |
| Add Safe | Vault **Add Safes** authorization. |
| Update Safe, Delete Safe | **Manage Safe** on the safe. |
| Add/Update/Delete Safe Member | **Manage Safe Members** on the safe. |
| Add/Delete Account Group Member | **Manage Safe** (account-group management) on the safe. |
| Add/Update/Delete User, Add User to Group | Vault **Add/Update Users** authorization. |
| Reset User Password | Vault **Audit Users** + **Reset Users Passwords**. |
| Activate User | Vault **Audit Users** + **Activate Users**. |
| Reconcile Credentials | **Initiate CPM account management operations** on the safe. |

For a retrieval-only FortiSOAR integration, **List Accounts + Retrieve Accounts**
on the target safe(s) is usually all that is needed.

---

## 7. Operations

### Accounts

**Get Accounts** — list accounts; supports search, filter, sort, pagination.

| Parameter | Type | Required |
|---|---|---|
| search | text | No |
| searchType | select | No |
| filter | text | No |
| savedfilter | select | No |
| sort | text | No |
| offset | integer | No |
| limit | integer | No |

**Get Account Details** — details of one account.

| Parameter | Type | Required |
|---|---|---|
| account_id | text | Yes |

**Retrieve Account Password** — retrieve the password / SSH key. Requires
Retrieve Accounts on the safe.

| Parameter | Type | Required |
|---|---|---|
| account_id | text | Yes |
| reason | text | No |
| TicketingSystemName | text | No |
| TicketId | text | No |
| ActionType | select | No |
| isUse | checkbox | No |

**Reconcile Credentials** — mark an account for CPM reconciliation.

| Parameter | Type | Required |
|---|---|---|
| account_id | text | Yes |

### Safes

**List Safes** — list safes visible to the authenticated user.

| Parameter | Type | Required |
|---|---|---|
| search | text | No |
| offset | integer | No |
| limit | integer | No |

**Get Safe Details** — details of one safe (by URL ID or name).

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |

**Add Safe** — create a safe.

| Parameter | Type | Required |
|---|---|---|
| safeName | text | Yes |
| description | text | No |
| managingCPM | text | No |
| numberOfDaysRetention | integer | No |
| numberOfVersionsRetention | integer | No |
| OLACEnabled | checkbox | No |

**Update Safe** — update safe properties.

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |
| safeName | text | No |
| description | text | No |
| managingCPM | text | No |
| numberOfDaysRetention | integer | No |
| numberOfVersionsRetention | integer | No |
| OLACEnabled | checkbox | No |

**Delete Safe** — delete an empty safe.

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |

### Safe members

**List Safe Members** — list members of a safe.

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |

**Add Safe Member** — add a member with permissions.

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |
| memberName | text | Yes |
| memberType | select | No |
| permissions | json | Yes |

**Update Safe Member** — update a member's permissions.

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |
| memberName | text | Yes |
| permissions | json | Yes |

**Delete Safe Member** — remove a member.

| Parameter | Type | Required |
|---|---|---|
| safeUrlId | text | Yes |
| memberName | text | Yes |

### Account groups

**Get Safe Account Groups** — account groups in a safe (by safe name).

| Parameter | Type | Required |
|---|---|---|
| safeName | text | Yes |

**Get Account Group Members** — members of an account group.

| Parameter | Type | Required |
|---|---|---|
| GroupID | text | Yes |

**Add Account Group Member** — add an account to a group.

| Parameter | Type | Required |
|---|---|---|
| GroupID | text | Yes |
| AccountID | text | Yes |

**Delete Account Group Member** — remove an account from a group.

| Parameter | Type | Required |
|---|---|---|
| GroupID | text | Yes |
| AccountID | text | Yes |

### Users

**Get Users** — list vault users.

| Parameter | Type | Required |
|---|---|---|
| search | text | No |
| userType | select | No |
| componentUser | checkbox | No |

**Get User Details** — details of one user.

| Parameter | Type | Required |
|---|---|---|
| userID | integer | Yes |

**Add User** — create a vault user.

| Parameter | Type | Required |
|---|---|---|
| username | text | Yes |
| initialPassword | password | Yes |
| firstName | text | No |
| lastName | text | No |
| email | text | No |
| enableUser | checkbox | No |
| changePassOnNextLogon | checkbox | No |
| vaultAuthorization | multiselect | No |

**Update User** — update a vault user.

| Parameter | Type | Required |
|---|---|---|
| userID | integer | Yes |
| firstName | text | No |
| lastName | text | No |
| enableUser | checkbox | No |
| changePassOnNextLogon | checkbox | No |

**Delete User** — delete a vault user.

| Parameter | Type | Required |
|---|---|---|
| userID | integer | Yes |

**Reset User Password** — reset a user's password. Requires Audit Users +
Reset Users Passwords.

| Parameter | Type | Required |
|---|---|---|
| userID | integer | Yes |
| newPassword | password | Yes |

**Activate User** — activate a suspended user.

| Parameter | Type | Required |
|---|---|---|
| userID | integer | Yes |

### User groups

**Get Groups** — list vault user groups.

| Parameter | Type | Required |
|---|---|---|
| search | text | No |

**Add User to Group** — add a user to a vault group.

| Parameter | Type | Required |
|---|---|---|
| groupId | integer | Yes |
| memberId | text | Yes |

### Session recordings

**Get Recordings** — list session recordings.

| Parameter | Type | Required |
|---|---|---|
| safe | text | No |
| fromTime | integer | No |
| toTime | integer | No |
| search | text | No |
| offset | integer | No |
| limit | integer | No |

**Get Recording Details** — details of one recording.

| Parameter | Type | Required |
|---|---|---|
| recording_id | text | Yes |

**Play Recording** — retrieve a recorded session data stream.

| Parameter | Type | Required |
|---|---|---|
| recording_id | text | Yes |

### Credentials (vault mode)

**Get Credentials** — list accounts in the configured vault safe. No parameters.

**Get Credentials Details** — account metadata for vault display.

| Parameter | Type | Required |
|---|---|---|
| secret_id | text | Yes |

**Get Credential** — retrieve the actual credential value.

| Parameter | Type | Required |
|---|---|---|
| secret_id | text | Yes |
| attribute_name | text | Yes |

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Failed to establish a new connection: [Errno -2] Name or service not known` on `*.id.cyberark.cloud` | Wrong Identity host. The tenant ID differs from the portal subdomain. Set **Identity Tenant URL** to the real host (section 3). |
| `access_denied – invalid client creds or client not allowed` | The user is not flagged "Is OAuth confidential client", the credentials are wrong, or an MFA policy is applied. Auth Type must be `ServiceUser`. |
| Health check hits `/Security/StartAuthentication` instead of `/oauth2/platformtoken` | Auth Type is set to `CyberArk` (interactive). Change it to `ServiceUser`. |
| Token succeeds but operations return 404 / time out | API host is wrong. Set **Privilege Cloud API URL** to the correct host. |
| Operation returns 403 | Token is valid but the user lacks the required CyberArk permission for that action (section 6). |
| Connector works from a workstation but not from the FortiSOAR agent | The agent lacks egress to the Identity / API hosts. Open 443 from the agent. |

---

## 9. Disclaimer

This is a community connector, not an official CyberArk or Fortinet product.
Validate in a non-production environment before deploying.
