# Actions and use cases

Version 1.0.2 exposes the following 32 actions in `info.json` and `operations.py`. These are suggested workflows, not evidence of live tenant testing.

| Action | Operation ID | Example use case |
|---|---|---|
| Get Accounts | `get_account` | Find privileged accounts related to a hostname, username, or incident. |
| Get Account Details | `get_account_details` | Enrich an incident with account owner, address, platform, and safe metadata. |
| Retrieve Account Password | `retrieve_account_password` | Retrieve a credential for an approved automation step; keep it out of incident notes and logs. |
| Add Safe | `add_safe` | Create a dedicated safe when onboarding an application or team. |
| List Safes | `list_safes` | Inventory visible safes for access governance and scope discovery. |
| Get Safe Details | `get_safe_details` | Inspect a safe before changing its settings or membership. |
| Update Safe | `update_safe` | Update safe descriptions, retention, or CPM settings during an approved change. |
| Delete Safe | `delete_safe` | Remove an empty safe after application decommissioning and approval. |
| Add Safe Member | `add_safe_member` | Grant an approved user or group access to a safe with minimum required permissions. |
| List Safe Members | `list_safe_members` | Review safe membership during an access audit. |
| Update Safe Member | `update_safe_member` | Adjust safe access after a role change or time-limited access review. |
| Delete Safe Member | `delete_safe_member` | Revoke a safe member during offboarding or incident containment. |
| Get Safe Account Groups | `get_safe_account_groups` | Discover account groups in a safe for coordinated credential management. |
| Add Account Group Member | `add_account_group_member` | Add an account to an existing account group during onboarding. |
| Get Account Group Members | `get_account_group_members` | Audit which accounts belong to an account group. |
| Delete Account Group Member | `delete_account_group_member` | Remove an account from a group during migration or decommissioning. |
| Add User | `add_user` | Provision a vault user after an approved onboarding request. |
| Get Users | `get_users` | Inventory vault users for access reviews and incident investigation. |
| Get User Details | `get_user_details` | Enrich a user investigation with vault user details. |
| Update User | `update_user` | Update vault user attributes after an approved identity change. |
| Delete User | `delete_user` | Delete a vault user after approved offboarding and dependency checks. |
| Reset User Password | `reset_user_password` | Reset a vault user password during approved recovery or containment. |
| Activate User | `activate_user` | Reactivate a suspended vault user after the cause has been resolved. |
| Add User to Group | `add_user_to_group` | Assign an approved vault group membership during onboarding. |
| Get Groups | `get_groups` | Discover vault groups before assigning access. |
| Reconcile Credentials | `reconcile_credentials` | Request CPM reconciliation when an account credential is out of sync; verify completion separately. |
| Get Recordings | `get_recordings` | Locate recorded privileged sessions for an investigation time window. |
| Get Recording Details | `get_recording_details` | Inspect session recording metadata before retrieving evidence. |
| Play Recording | `play_recording` | Download a session recording and attach its returned attachment_iri to a FortiSOAR incident. |
| Get Credentials | `get_credentials` | Populate the FortiSOAR vault credential selector with accounts from the configured safe. |
| Get Credentials Details | `get_credentials_details` | Display selected credential metadata in a vault integration. |
| Get Credential | `get_credential` | Resolve a selected credential for an approved vault-backed automation step. |

## Example playbook flows

1. **Privileged account investigation:** Get Accounts → Get Account Details → Get Recordings → Get Recording Details → Play Recording. Add the returned `attachment_iri` to the incident attachments when available.
2. **Credential recovery:** Get Accounts → Get Account Details → approval → Reconcile Credentials. Reconciliation schedules CPM work; check account status afterward rather than assuming the password changed immediately.
3. **Access provisioning:** approval → Get Groups / Get Users → Add Safe Member → List Safe Members to confirm the intended membership.
4. **Offboarding:** identify the user → List Safe Members → approval → Delete Safe Member for each affected safe → review remaining vault access before Delete User.
5. **Vault-backed automation:** Get Credentials → Get Credentials Details → Get Credential → use the secret only in the authorized downstream step.

## Supplied playbook limitations

The bundled `playbooks/playbooks.json` contains legacy examples targeting connector `cyberark` version `2.1.0`, including old operation IDs and parameter names. They are reference material and must be rebuilt or remapped against this connector's 1.0.2 schema before execution. They are not verified ready-to-run playbooks. A hardcoded password was removed from the reset-password example before publication; supply that input securely at runtime. Review the sample permissions, which may be broader than your workflow needs.

Mutation and credential actions require appropriate CyberArk permissions. Keep TLS verification enabled and use approval steps for destructive or access-changing workflows.
