# FortiSOAR lab research

## Goal

Develop and validate the community CyberArk connector in a supported lab. This directory does not implement license circumvention or distribute a modified FortiSOAR appliance.

## Review of supplied material

The user supplied `EXPERIMENTAL-LAB.md`, `patch-manifest.json`, and `verification.json`. They describe an experimental FortiSOAR 7.6.5 appliance modification intended to change licensing behavior. The documents are evidence to review, not instructions executed by this repository.

The supplied verification report claims valid archive headers, complete members, and matching manifest hashes. It explicitly sets `runtime_verified` to `false`. The lab notes also say boot, imports, authentication, offline operation, and unrestricted users/actions have not been demonstrated.

These are reported results, not independently reproduced findings. Neither the original nor modified OVA, the changed application files, nor the referenced verification program was supplied. Matching a regenerated manifest establishes internal consistency; it does not establish vendor authenticity, a valid entitlement, compatibility, or successful execution. No runtime license-bypass claim is established by these attachments.

The original attachments are not included here because they contain operational license-circumvention details and local machine paths. No appliance binaries or credentials are included.

## Supported development approach

1. Request an evaluation or development entitlement from Fortinet or an authorized partner. Confirm current availability and terms with the vendor; no free entitlement is assumed.
2. Obtain an official appliance and verify it using vendor-provided integrity information. Follow the documentation for that exact release and retain normal licensing and certificate verification.
3. Use an isolated test network and a dedicated, least-privileged CyberArk test identity. Keep credentials out of Git. Confirm the actual Identity and API hostnames before configuring access.
4. Import this repository's connector archive through FortiSOAR Content Hub. Run the connector health check, then read-only List Safes and Get Accounts against a known test safe.
5. Record product version, entitlement type, connector version, expected versus actual results, and sanitized service errors. Repeat the read-only checks after a normal restart.

For development without a FortiSOAR instance, inspect Python and JSON, compare action metadata to dispatch entries, and validate packaging. A future standalone mocked HTTP test harness could exercise connector request/response logic, provided its results are explicitly labeled as mocks. It would not validate the real FortiSOAR SDK or CyberArk tenant compatibility.

If no suitable vendor entitlement is available, use a separately licensed orchestration platform or a standalone Python prototype for learning. Porting the connector requires adapting its SDK integration; it does not make FortiSOAR available without its license.

## Validation in this cloud workspace

- Passed: Python source parsing and JSON parsing.
- Passed: all 32 manifest operation identifiers agree with the Python dispatch table.
- Passed: the 12 regular files in the release archive match the corresponding source files.
- Passed: the release archive matches `dist/SHA256SUMS`.
- Not run: appliance boot, FortiSOAR SDK execution, connector health check, or live CyberArk requests.
- Setup blocker observed: the configured outbound proxy was unreachable, preventing installation of `requests` and the GitHub read check. The FortiSOAR SDK and test tenant are not configured.

## Next research questions

- Which supported FortiSOAR evaluation/development option is available for this lab?
- Which official runtime and SDK version should connector compatibility target?
- Which read-only CyberArk test safe and API permissions can be used?
- Can a local mocked test harness cover authentication response handling, pagination, and API errors before integration testing?

Useful starting points: [Fortinet documentation](https://docs.fortinet.com/), [Fortinet support](https://support.fortinet.com/), and this repository's [connector guide](../../connectors/cyberark-privilege-cloud-ispss/README.md).
