# Update: integration guide and action examples for CyberArk Privilege Cloud ISPSS

I have expanded the documentation for my community FortiSOAR connector, **CyberArk Privilege Cloud (ISPSS) v1.0.2**. Created by **dhaneshwar (@dhn0x)** and released under the **MIT License**.

The connector supports ISPSS and Privilege Cloud Standard, with 32 actions covering accounts, credentials, safes, safe members, account groups, vault users/groups, and session recordings.

## How to integrate

1. Download the connector `.tgz` from [GitHub dist](https://github.com/dhn0x/FortiSOAR/tree/main/dist), then import it using **Content Hub → Manage → Add Connector**.
2. Prepare a dedicated CyberArk automation service user. For ISPSS client-credentials authentication, enable **Is OAuth confidential client** and use an approved policy permitting that flow. Keep human-user MFA policies in place.
3. Grant access to the required safes and only the permissions needed by your playbooks. For lookup/retrieval, start with List Accounts and Retrieve Accounts.
4. Create a connector configuration. Set Server URL to your portal host, Identity Tenant URL to the actual Identity tenant host, and Privilege Cloud API URL to the API host. Use **host URLs only**; do not append API or token paths. The Identity tenant ID can differ from the portal subdomain.
5. Select **ServiceUser** for ISPSS automation, enter the service-user login and password securely, and keep **Verify SSL** enabled. Standard deployments use their supported CyberArk/LDAP/RADIUS authentication.
6. Ensure the executing FortiSOAR node/agent can reach both hosts over HTTPS, run health check, then test List Safes and Get Accounts with a known safe.

## How to use the actions

In a test playbook, add a connector step, select **CyberArk Privilege Cloud (ISPSS)** and your saved configuration, then choose an action. Use the output picker to pass verified IDs into subsequent steps.

- **Account investigation:** Get Accounts → verify the matching account in `value` → pass its `id` as `account_id` to Get Account Details.
- **Credential retrieval:** after approval, pass `account_id` to Retrieve Account Password with a reason/ticket. Pass the returned `password` directly to the authorized downstream step; keep it out of incident notes and logs.
- **Safe access:** List Safes → select `safeUrlId` → List Safe Members → approval → Add/Update Safe Member with explicit permissions → List Safe Members to verify.
- **Credential reconciliation:** verify the account → approval → Reconcile Credentials. This submits CPM work; verify completion separately.
- **Recording evidence:** Get Recordings → Get Recording Details → Play Recording. Append a nonempty returned `attachment_iri` to the incident's existing attachments. Handle the base64 fallback if FortiSOAR attachment utilities are unavailable.
- **Vault mode:** enable Use As Vault and enter Vault Safe Name. Get Credentials returns `key` values; use a selected key as `secret_id` for credential metadata/retrieval. For Get Credential, set `attribute_name` to `Password`.

Parameter names are case-sensitive. Legacy bundled playbooks need remapping from the older `cyberark` connector; they are reference examples rather than ready-to-run imports.

[Full integration walkthrough and JSON input examples for all 32 actions](https://github.com/dhn0x/FortiSOAR/blob/main/connectors/cyberark-privilege-cloud-ispss/INTEGRATION_AND_ACTION_EXAMPLES.md)

[Action use cases](https://github.com/dhn0x/FortiSOAR/blob/main/connectors/cyberark-privilege-cloud-ispss/ACTIONS_AND_USE_CASES.md) · [Configuration reference](https://github.com/dhn0x/FortiSOAR/blob/main/connectors/cyberark-privilege-cloud-ispss/DOCUMENTATION.md)

This is a community connector, not an official CyberArk or Fortinet product. Examples require validation in your own FortiSOAR/CyberArk environment.
