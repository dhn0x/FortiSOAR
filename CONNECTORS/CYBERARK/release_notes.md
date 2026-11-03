# CyberArk Privilege Cloud (ISPSS) Connector — Release Notes

## Version 1.0.2

### Changed
- **Play Recording** now saves the recording as a FortiSOAR **attachment**
  (via `upload_file_to_cyops(file_path=..., create_attachment=True)`) and
  returns the **`attachment_iri`** (plus `file_iri`). The recording therefore
  appears as a normal downloadable attachment on the alert/record, and a
  playbook can append `attachment_iri` to the record's `attachments` field -
  the same pattern used to attach a report PDF. The raw video bytes are still
  read as-is (never text-decoded), so the saved `.avi` is valid and playable.
- `info.json` output schema for Play Recording updated to expose
  `attachment_iri` and the `file` metadata.

## Version 1.0.1

### Fixed
- **Play Recording** now returns the session recording as a FortiSOAR **file
  attachment** instead of inline data. Previously the recording was read via
  `response.text`, which text-decoded the binary video (corrupting the bytes
  into U+FFFD replacement characters) and pushed the whole blob into the
  playbook record. On real (multi-minute to multi-hour) sessions that blob is
  tens of MB, which caused the playbook step to hang **"In Progress"**.
- The recording is now read as raw bytes (`_request_bytes`, never text-decoded),
  so the stored `.avi` is a valid, playable file. The file extension is derived
  from the response `Content-Type`, falling back to the file's magic bytes
  (`RIFF`/`AVI` → `.avi`).
- When the FortiSOAR file module is unavailable (e.g. local testing), the action
  falls back to returning intact base64 instead of corrupted text.

## Version 1.0.0

First public release.

### Overview
A FortiSOAR connector for CyberArk Privilege Cloud that supports both the
Identity Security Platform Shared Services (ISPSS) deployment and the legacy
Privilege Cloud Standard deployment. It uses the CyberArk Privilege Cloud
REST API (Gen 2).

### Authentication
- **ServiceUser** (recommended for automation): OAuth2 client-credentials flow
  against the Identity `/oauth2/platformtoken` endpoint. The `client_id` /
  `client_secret` are the CyberArk Identity service user's login name and
  password.
- **CyberArk / LDAP / RADIUS**: interactive Identity authentication for cases
  where a service user is not used. Note that an account with an MFA policy
  cannot complete non-interactive logon.

### ISPSS host handling
On ISPSS tenants the Identity tenant ID is frequently **not** the same as the
portal subdomain (for example, portal `acme.cyberark.cloud` but Identity host
`abc1234.id.cyberark.cloud`). The connector exposes two optional fields,
**Identity Tenant URL** and **Privilege Cloud API URL**:

- Set **Identity Tenant URL** to the real Identity host when it differs from the
  portal subdomain.
- Leave both blank to auto-derive `<subdomain>.id.cyberark.cloud` and
  `<subdomain>.privilegecloud.cyberark.cloud`.

To find the Identity tenant URL, open the portal in a browser and read the host
it redirects to (`https://<tenant-id>.id.cyberark.cloud`), or ask CyberArk
support.

### Operations
Accounts, Safes, Safe Members, Account Groups, Users, User Groups, Session
Recordings, and credential retrieval / reconciliation. See the README for the
full list.
