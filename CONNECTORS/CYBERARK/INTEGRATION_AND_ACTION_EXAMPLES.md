# Integrating CyberArk Privilege Cloud ISPSS with FortiSOAR

Created by **dhaneshwar (@dhn0x)** · Connector **1.0.2** · MIT License

## 1. Prepare CyberArk and network access

Use a dedicated automation identity authorized by your CyberArk administrator. For ISPSS, configure a service user with **Is OAuth confidential client** enabled and a policy that permits the connector's non-interactive client-credentials flow. Keep human-user MFA policies in place. Assign the role needed for Privilege Cloud API access and membership in the required safes. For account lookup and credential retrieval, begin with List Accounts and Retrieve Accounts; grant administration rights only for the actions you intend to use. Exact permissions depend on the API and tenant policy; confirm them with your CyberArk administrator.

Allow outbound HTTPS from the FortiSOAR node or executing agent to both the Identity and Privilege Cloud API hosts. Ensure DNS resolution and trusted TLS certificates work from that node.

## 2. Install and configure

1. Download `cyberark-privilege-cloud-ispss-1.0.2.tgz` from the repository's `CONNECTORS/CYBERARK/dist/` directory using the raw download option. Optionally compare its SHA-256 with `CONNECTORS/CYBERARK/dist/SHA256SUMS`.
2. Import it through **Content Hub → Manage → Add Connector**. Menu labels can vary by FortiSOAR release.
3. Open **CyberArk Privilege Cloud (ISPSS)** and create a named configuration, for example `CyberArk-ISPSS-Lab`.
4. Enter the configuration below, substituting your actual hosts and identity. Save credentials only in the connector's protected configuration fields.

| Field | Example / setting |
|---|---|
| Server URL | `https://acme.cyberark.cloud` |
| Identity Tenant URL | `https://abc1234.id.cyberark.cloud` — obtain the actual tenant host from your administrator or portal redirect |
| Privilege Cloud API URL | `https://acme.privilegecloud.cyberark.cloud` |
| Authentication Type | `ServiceUser` for ISPSS automation |
| Username / Client ID | Dedicated Identity service-user login |
| Password / Client Secret | Service-user password, entered securely |
| Use As Vault | False for initial action testing |
| Verify SSL | True |

Enter **host URLs only**, without `/PasswordVault/API` or `/oauth2/platformtoken`: the implementation appends endpoint paths. Explicit Identity/API overrides are used only for ISPSS. For Standard, set Server URL to `https://acme.privilegecloud.cyberark.com` and use CyberArk, LDAP, or RADIUS as supported by your tenant. The default auth type is CyberArk, so explicitly select ServiceUser for ISPSS service-user authentication.

5. Run the configuration health check. Then run **List Safes** and **Get Accounts** against a known test safe. A successful health check alone does not prove the identity has access to the target accounts or recordings.

## 3. Use an action in a playbook

1. Create or open a test playbook and add a connector action step.
2. Select **CyberArk Privilege Cloud (ISPSS)**, your saved configuration, and the action title from the reference below.
3. Fill the action's input fields. JSON examples below represent the **operation parameters**, not the complete FortiSOAR workflow-export format; do not include authentication credentials in them.
4. Run the step on a test record and inspect its structured result. Use FortiSOAR's dynamic-value picker to map actual results into the next step; step result wrappers vary by release.
5. Handle empty lists and failures before continuing. For account selection, verify safe, username, and address, then pass the selected `id` as `account_id`. Do not automatically choose the first match in an administrative workflow.
6. For production playbooks, add approvals for credential disclosure, access changes and deletion, and avoid logging secret outputs.

Inputs are case-sensitive: `account_id`, `safeUrlId`, `userID`, `GroupID` / `AccountID`, and `groupId` / `memberId` are different fields. Replace example IDs with values returned by your tenant.

## 4. Practical flows and output mapping

### Account investigation and credential retrieval

Run **Get Accounts** with `search: server01`, `filter: safeName eq AutomationSafe`, and `limit: 10`. Inspect its `value` list and choose the verified account. Pass that account's `id` into **Get Account Details** as `account_id`. After approval, pass the same ID into **Retrieve Account Password**, with a meaningful `reason` and your ticket ID. Its result is an object containing `password`; map that value directly to the authorized consuming step, rather than writing it into incident descriptions or notes.

### Safe membership provisioning

Use **List Safes** to find the target safe, then pass its `safeUrlId` to **Get Safe Details** and **List Safe Members**. After approval, use **Add Safe Member** with the intended `memberName`, `memberType`, and an explicit `permissions` JSON object. The example below grants list/retrieve permissions for illustration; tailor the full permission set to your policy. Re-run List Safe Members and compare the intended membership and permissions. For Update Safe Member, review the full intended permission set; do not assume unspecified flags are preserved.

### Reconcile an out-of-sync account

Find and verify the account, obtain approval, then run **Reconcile Credentials** with its `account_id`. A successful response means the reconciliation request was submitted. It does not prove CPM has completed reconciliation. Check the account's management status in CyberArk and use Get Account Details afterward to inspect available status fields.

### Retrieve a session recording as incident evidence

Run **Get Recordings**, inspect `Recordings`, and obtain the recording ID from the actual response. Pass it as `recording_id` to **Get Recording Details** and then **Play Recording**. Version 1.0.2 downloads binary content and attempts to store it as a FortiSOAR attachment. When a nonempty `attachment_iri` is returned, use a record-update step to append that IRI to the incident's existing attachments, preserving them. Do not insert the raw recording into a text field. If `content_base64` and a fallback note are returned instead, attachment creation was unavailable; handle that branch explicitly and investigate FortiSOAR file utility compatibility. The action downloads a file; it does not launch an embedded video player.

### Use FortiSOAR vault integration

Enable **Use As Vault** and enter **Vault Safe Name** in the configuration, then rerun health check. Register/select this configuration through the vault integration supported by your FortiSOAR release. **Get Credentials** lists `{key, display_name}` items; pass the selected `key` as `secret_id` to **Get Credentials Details** or **Get Credential**. The latter also requires `attribute_name` in its form; use `Password`. The current implementation always returns `password` and does not select another attribute based on this field. Get Credentials requests up to 1,000 accounts and does not automatically paginate; larger safes need separate handling.

## 5. Action input examples

Examples are illustrative and have not been executed against a live tenant. Use secure runtime inputs for placeholder passwords; never paste a fixed secret into a published playbook. Read actions can still disclose sensitive metadata or credentials.

### Get Accounts (`get_account`)

Find privileged accounts related to a hostname, username, or incident.

```json
{
  "search": "server01",
  "filter": "safeName eq AutomationSafe",
  "limit": 10,
  "offset": 0
}
```

### Get Account Details (`get_account_details`)

Enrich an incident with account owner, address, platform, and safe metadata.

```json
{
  "account_id": "25_6"
}
```

### Retrieve Account Password (`retrieve_account_password`)

Retrieve a credential for an approved automation step; keep it out of incident notes and logs.

```json
{
  "account_id": "25_6",
  "reason": "Approved incident investigation",
  "TicketId": "INC-1234"
}
```

### Add Safe (`add_safe`)

Create a dedicated safe when onboarding an application or team.

```json
{
  "safeName": "AutomationSafe"
}
```

### List Safes (`list_safes`)

Inventory visible safes for access governance and scope discovery.

```json
{
  "search": "AutomationSafe",
  "limit": 10
}
```

### Get Safe Details (`get_safe_details`)

Inspect a safe before changing its settings or membership.

```json
{
  "safeUrlId": "AutomationSafe"
}
```

### Update Safe (`update_safe`)

Update safe descriptions, retention, or CPM settings during an approved change.

```json
{
  "safeUrlId": "AutomationSafe",
  "description": "Approved automation safe"
}
```

### Delete Safe (`delete_safe`)

Remove an empty safe after application decommissioning and approval.

```json
{
  "safeUrlId": "AutomationSafe"
}
```

### Add Safe Member (`add_safe_member`)

Grant an approved user or group access to a safe with minimum required permissions.

```json
{
  "safeUrlId": "AutomationSafe",
  "memberName": "svc_fortisoar",
  "permissions": {
    "listAccounts": true,
    "retrieveAccounts": true
  }
}
```

### List Safe Members (`list_safe_members`)

Review safe membership during an access audit.

```json
{
  "safeUrlId": "AutomationSafe"
}
```

### Update Safe Member (`update_safe_member`)

Adjust safe access after a role change or time-limited access review.

```json
{
  "safeUrlId": "AutomationSafe",
  "memberName": "svc_fortisoar",
  "permissions": {
    "listAccounts": true,
    "retrieveAccounts": true
  }
}
```

### Delete Safe Member (`delete_safe_member`)

Revoke a safe member during offboarding or incident containment.

```json
{
  "safeUrlId": "AutomationSafe",
  "memberName": "svc_fortisoar"
}
```

### Get Safe Account Groups (`get_safe_account_groups`)

Discover account groups in a safe for coordinated credential management.

```json
{
  "safeName": "AutomationSafe"
}
```

### Add Account Group Member (`add_account_group_member`)

Add an account to an existing account group during onboarding.

```json
{
  "GroupID": "25_10",
  "AccountID": "25_6"
}
```

### Get Account Group Members (`get_account_group_members`)

Audit which accounts belong to an account group.

```json
{
  "GroupID": "25_10"
}
```

### Delete Account Group Member (`delete_account_group_member`)

Remove an account from a group during migration or decommissioning.

```json
{
  "GroupID": "25_10",
  "AccountID": "25_6"
}
```

### Add User (`add_user`)

Provision a vault user after an approved onboarding request.

```json
{
  "username": "automation_test_user",
  "initialPassword": "<secure runtime input>"
}
```

### Get Users (`get_users`)

Inventory vault users for access reviews and incident investigation.

```json
{
  "search": "automation_test_user"
}
```

### Get User Details (`get_user_details`)

Enrich a user investigation with vault user details.

```json
{
  "userID": 42
}
```

### Update User (`update_user`)

Update vault user attributes after an approved identity change.

```json
{
  "userID": 42,
  "firstName": "Automation",
  "lastName": "User"
}
```

### Delete User (`delete_user`)

Delete a vault user after approved offboarding and dependency checks.

```json
{
  "userID": 42
}
```

### Reset User Password (`reset_user_password`)

Reset a vault user password during approved recovery or containment.

```json
{
  "userID": 42,
  "newPassword": "<secure runtime input>"
}
```

### Activate User (`activate_user`)

Reactivate a suspended vault user after the cause has been resolved.

```json
{
  "userID": 42
}
```

### Add User to Group (`add_user_to_group`)

Assign an approved vault group membership during onboarding.

```json
{
  "groupId": 7,
  "memberId": "automation_test_user"
}
```

### Get Groups (`get_groups`)

Discover vault groups before assigning access.

```json
{
  "search": "Automation"
}
```

### Reconcile Credentials (`reconcile_credentials`)

Request CPM reconciliation when an account credential is out of sync; verify completion separately.

```json
{
  "account_id": "25_6"
}
```

### Get Recordings (`get_recordings`)

Locate recorded privileged sessions for an investigation time window.

```json
{
  "safe": "RecordingsSafe",
  "limit": 10
}
```

### Get Recording Details (`get_recording_details`)

Inspect session recording metadata before retrieving evidence.

```json
{
  "recording_id": "<recording ID from Get Recordings>"
}
```

### Play Recording (`play_recording`)

Download a session recording and attach its returned attachment_iri to a FortiSOAR incident.

```json
{
  "recording_id": "<recording ID from Get Recordings>"
}
```

### Get Credentials (`get_credentials`)

Populate the FortiSOAR vault credential selector with accounts from the configured safe.

```json
{}
```

### Get Credentials Details (`get_credentials_details`)

Display selected credential metadata in a vault integration.

```json
{
  "secret_id": "25_6"
}
```

### Get Credential (`get_credential`)

Resolve a selected credential for an approved vault-backed automation step.

```json
{
  "secret_id": "25_6",
  "attribute_name": "Password"
}
```

## 6. Common problems

| Problem | What to check |
|---|---|
| Wrong Identity endpoint or DNS failure | Use the actual Identity tenant host; it may differ from the portal subdomain. |
| Authentication fails | Confirm ServiceUser selection for ISPSS automation, protected credential fields, confidential-client setting, and permitted authentication policy. |
| HTTP 403 on an action | Check safe membership and action-specific vault permissions; successful login alone is insufficient. |
| HTTP 404 or repeated API path | Use a host-only API URL and verify the resource ID and tenant API host. |
| No accounts returned | Check safe membership, search/filter values and pagination; an empty list is not necessarily an authentication failure. |
| Password reset or user creation fails | Supply the password securely at runtime and verify vault permissions and password policy. |
| No recording attachment | Inspect the action's fallback note and FortiSOAR file utility support; preserve existing incident attachments when appending. |
| Bundled playbook fails | Legacy examples target `cyberark` 2.1.0 and contain older action/parameter names. Build a new step using this connector's current schema. |

The bundled playbooks are reference material, not tested imports for this connector. No live FortiSOAR/CyberArk validation or exact FortiSOAR release certification is claimed. See [the connector guide](DOCUMENTATION.md) for field reference and [action use cases](ACTIONS_AND_USE_CASES.md) for workflow ideas.
