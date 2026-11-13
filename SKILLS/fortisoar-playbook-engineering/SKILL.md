---
name: "fortisoar-playbook-engineering"
description: "Design, build, review, debug and upgrade FortiSOAR playbooks to Fortinet's own standard (SOAR Framework patterns). Use for any FortiSOAR playbook, trigger, Jinja, loop, approval or playbook JSON export question."
---

# FortiSOAR Playbook Engineering

A general, org-agnostic standard for building FortiSOAR playbooks the way Fortinet builds its
own content. Derived from the SOAR Framework solution pack (154 playbooks + 30 reference blocks),
use-case solution packs (e.g. Phishing Incident Management), connector sample playbooks, and the
FortiSOAR Playbooks Guide. Org-specific details (modules, picklists, connectors, teams) plug in
on top — never hard-code them into the design.

## 0. Pick the mode first

| User asks… | Mode | Deliverable |
|---|---|---|
| "Build/make a playbook for X" | **Design** | Collection + playbook map, then step-by-step build sheet (§10) |
| "How do I configure step/trigger/loop…" | **Build** | Exact UI settings + Jinja for that step |
| Shares an exported JSON / zip | **Review** | Findings against the checklist (§11), severity-ranked, with fixes |
| "Playbook failing / looping / slow" | **Debug** | Diagnosis procedure (§12) |
| "Make this playbook better/advanced" | **Upgrade** | Apply the maturity ladder (§9) one level at a time |

If the use case is vague, ask at most: trigger source (SIEM alert / email / manual / API / schedule),
target module, and which response actions are allowed automatically vs need approval.
Then proceed with sensible defaults and state them.

## 1. Architecture — how Fortinet layers playbooks

Never build one giant playbook. Fortinet's framework is a **pipeline of small playbooks** in
numbered collections that reflect execution order:

| Collection | Role | Typical trigger |
|---|---|---|
| 01 - Drafts | Work in progress, never active in prod | — |
| 02 - Use Cases | Use-case orchestrators (Phishing, Brute Force…) | On Create (filtered) / Manual |
| 03 - Enrich | Indicator extraction + pluggable enrichment | On Create / Referenced |
| 03 - Triage | Priority weight, severity, correlation, similar alerts | On Update / Referenced |
| 04 - Actions | Block/unblock/isolate per indicator type | Manual / Referenced |
| 05 - Hunt | IOC hunts across SIEM/EDR | On Create (hunt) / Manual |
| 06 - IRP - * | Case mgmt (SLA dates, escalation), comms, war room, reporting | On Create / On Update / Manual |
| 07 - Case Response Plan | Task sets per case type (NIST 800-61) | On Create / Manual |
| 08 - Utilities | Generic subroutines (create & link asset, download attachment) | Referenced |

Rules derived from this:
1. **One playbook = one job.** Fortinet's average playbook is ~6 steps; the largest ~27. If a design
   exceeds ~25 steps, split into an orchestrator + referenced children.
2. **Orchestrator → subroutines.** Trigger playbooks stay thin: gather context, decide, call
   referenced playbooks. Business logic lives in `#Subroutine` playbooks with declared parameters.
3. **Pluggable, not hard-wired.** Enrichment and actions are discovered at runtime (see §6.9) so new
   connectors plug in without editing the core playbook.
4. **Separate org layer.** Put org specifics (domains, subnets, weights, team, thresholds) in one
   `Configuration` step or in Global Variables / the `keys` module — never scattered in steps.

## 2. Triggers

| Trigger | Use for | Export signature (Start step) |
|---|---|---|
| **On Create** | Automate on new records (alert ingested) | stepType `ea155646…`, `resource`, `fieldbasedtrigger` |
| **On Update** | React to a field change (status, state, reputation) | stepType `9300bf69…`, `fieldbasedtrigger` with `operator: changed` |
| **Manual** | Analyst button, optional input form | stepType `f414d039…`, `route`, `title`, `executeButtonText`, `inputVariables`, `displayConditions`, `noRecordExecution`, `singleRecordExecution` |
| **Referenced** | Child/subroutine called by another playbook | stepType `b348f017…`, no record trigger; inputs via playbook `parameters` |
| **Custom API Endpoint** | External system pushes data | `route` (string path), `authentication_methods`; data in `vars.request.data` |
| **Schedule** | Periodic jobs (ingestion, cleanup, reports) | Created via Schedules on a no-record/referenced playbook |

Trigger rules:
- **Always filter On Create/On Update.** Use trigger conditions (e.g. `type == Phishing`,
  `state == New`). For On Update, combine `Is Changed` on the field with the target value
  (Fortinet: `state changed AND state == Investigated`). An unfiltered On Update is a defect.
- **Loop danger:** an On Create/On Update playbook that updates its own record or creates records in
  the same module can re-trigger itself endlessly. Prevent with: precise conditions, a guard field
  (e.g. only fire when `enrichmentStatus != Completed`), and updating only fields that are not in the
  trigger condition. Platform safety nets exist (`skip_recursive_playbook_execution` in
  `/opt/cyops-api/config/parameters_prod.yaml`, `REF_SELF_PB_LOOP_LEVEL` = 10) — don't rely on them.
- **Kill switch for a running loop:** set the playbook Inactive; queued runs drain, no new ones start.
- **Bulk ingest does not fire On Create/On Update.** Records created by the *Ingest Bulk Feed* step
  skip triggers — call the processing playbook explicitly afterwards.
- One update action fires On Update **once** even if many fields change; multiple inline edits fire
  it several times; a bulk edit once.
- Multi-node / HA: "Only trigger at the node where record is" (exported as `triggerOnSource` /
  `triggerOnReplicate`) — keep default `triggerOnSource: true`, `triggerOnReplicate: false`.
- Manual triggers: `singleRecordExecution: true` = one record only; "Run once for all selected
  records" passes all as an array; `noRecordExecution: true` = button without selecting a record
  (ingestion, imports). Use `displayConditions` to show the button only where relevant
  (e.g. only on `type == Phishing` alerts, or hide "Escalate" once already escalated).
- Make dual-entry playbooks: the same playbook works when triggered on a record **or** called with
  params (see §5 ternary pattern). Fortinet does this everywhere.

## 3. Step types (UI name ↔ export UUID prefix)

| UI step | stepType prefix | Key arguments in export |
|---|---|---|
| Set Variable | `04d0cf46` | each key = a variable |
| Decision | `12254cf5` | `conditions[]` with `option`, `condition`, `step_iri`, one `default: true` |
| Create Record | `2597053c` | `collection`, `resource`, `operation`, `__replace`, `__fieldsToUpdate`, `for_each` |
| Update Record | `b593663d…722` | `collection` (IRI), `collectionType`, `resource`, `operation` Append/Overwrite, `__link` |
| Find Records | `b593663d…770` | `module` (`alerts?$limit=30`), `query` filters, `__selectFields` |
| Connector (any) | `0bfed618` / `0109f35d` (Utilities) | `connector`, `operation`, `config`, `params`, `pickFromTenant` |
| Reference a Playbook | `74932bdc` | `workflowReference`, `arguments`, `apply_async`, `pass_input_record`, `pass_parent_env` |
| Manual Input / Approval | `fc04082a`, `a19333c2` | `type` InputBased/DecisionBased, `is_approval`, `owner_detail`, `response_mapping`, `timeout` |
| Manual Task | `dc6ac63d` | `resource` (task), `collection: tasks` |
| Wait | `6832e556` | `delay` or `type: ConditionBased` + `rule` + `timeout` |
| Send Email | `4c0019b2` | `connector: smtp`, `send_email_new` |
| Ingest Bulk Feed | `7b221880` | `collection: /api/ingest-feeds/<module>`, `for_each.__bulk` |
| Code Snippet | `1fdd14cc` | `code-snippet` / `python_inline_code_editor` — last resort |

Step Utilities available on most steps: `when` (run condition), `for_each` (loop), `do_until`
(retry), `ignore_errors`, `message` (post comment on record), `step_variables` (capture output),
`mock_result` (test data).

Most-used built-in Utilities ops (`cyops_utilities`): `no_op` (Exit/merge point),
`make_cyops_request` (FortiSOAR API), `query_cyops_resource`, `update_cyops_resource`,
`extract_artifacts_new`, `ip_cidr_check`, `api_call` (generic REST), `format_richtext`,
`raise_exception`, `updatemacro` (write Global Variable), `create_cyops_attachment`,
`download_file_from_url`, `unzip_protected_file`.

## 4. Standard playbook skeleton

Every Fortinet playbook follows this shape. Use it as the default:

```
Start (trigger, filtered)
  → Configuration        [Set Variable: all inputs, IRIs, thresholds, org constants]
  → Guard decision(s)    [Decision: right type? already processed? dedicated tenant?]
       ├─ No  → Exit     [Utilities: No Operation]  (+ optional comment why)
       └─ Yes → Work     [connector / reference playbooks / find records]
                → Compute [Set Variable: verdict, score]
                → Decision on result
                → Update Record (+ message comment)  → Exit
```

- **Configuration step is mandatory** and always first after Start. All later steps reference
  `vars.<name>` from it, never raw `vars.input.records[0]…` repeatedly.
- **Every decision has a `default` branch.** Decisions with no default leave the playbook stuck.
- **End branches in `No Operation` named Exit/Stop/Do Nothing** so the flow has explicit end points.
- **Report back on the record**: update status/state fields and post a comment (via the `message`
  step utility) so the analyst sees what automation did without opening the logs.

## 5. Variables and data access

| Expression | Meaning |
|---|---|
| `vars.input.records[0]` | Triggering record (On Create/Update/Manual) |
| `vars.input.records` | All selected records (manual, run-once) |
| `vars.input.params.<name>` | Parameter passed by parent playbook / manual form |
| `vars.request.data` | Body of a Custom API Endpoint call |
| `vars.steps.<Step_Name>` | Output of a step — spaces in step name become `_` |
| `vars.result` | Current step's output — use inside `step_variables` and `do_until` |
| `vars.item` | Current element inside a `for_each` loop |
| `globalVars.<Name>` | Global Variable (org constants, feature flags, pluggable lists) |
| `vars.<name>` | Anything set by Set Variable or `step_variables` |

Patterns:
- **Dual-entry input** (works as triggered or referenced):
  `{{vars.input.params.alert_iri | ternary(vars.input.params.alert_iri, vars.input.records[0]['@id'])}}`
- **Capture output immediately** with `step_variables` on the step itself
  (`isFound: "{% if vars.result.data %}true{% else %}false{% endif %}"`) instead of a separate
  Set Variable step.
- **Rename steps before referencing them.** `vars.steps.Get_IP_Reputation` breaks silently if
  the step is renamed later — finalise names first.
- **Mock data:** set `useMockOutput: true` in Configuration (case-sensitive) and fill
  `mock_result` on connector steps to develop without a live integration. Fortinet packs gate it
  with `useMockOutput: {{globalVars.Demo_mode}}`.

## 6. Core patterns (copy these)

### 6.1 Loops
| Mode | Setting | Use when |
|---|---|---|
| **Bulk** | `for_each.__bulk: true`, `batch_size: 100–200` | Create/Update Record over many items — **default choice** |
| Sequential | `parallel: false` | Order matters, or the API rate-limits |
| Parallel | `parallel: true` | Independent, slow calls (enrichment fan-out) |

- Filter inside the loop with `for_each.condition` (e.g. `{{vars.item.value != "NA"}}`) instead of
  pre-filtering with an extra step.
- Collect loop output: `{{vars.steps.Create_Indicator | json_query('[]."@id"') | unique}}`.
- Do not combine `do_until` with `when` or `for_each` on the same step.

### 6.2 Retry / poll (do_until)
For async jobs (sandbox detonation, export jobs):
`do_until: {condition: "{{vars.result.data.status == 'FINISHED'}}", retries: 10, delay: 30}`.
Default is 3 retries × 5 s — always set explicit values. Total wait = retries × delay; size it to
the real job duration, and handle the "still not done" case after the step.

### 6.3 Wait for something to happen
Condition-based Wait (resume when indicators finish enrichment) **with a timeout branch**:
Fortinet waits max 2 minutes, then posts "Enrichment did not complete in the default wait time"
and continues. Never wait without a timeout path.

### 6.4 Error handling — three tools
1. **Ignore Error + flag + decision** (soft failure, e.g. one TI source down):
   step `ignore_errors: true`, `step_variables: isFound: {% if vars.steps.X.data %}true{% else %}false{% endif %}`,
   then a Decision on `vars.isFound`. The step log still shows "Finished with Error".
2. **Raise Exception** (hard failure, wrong usage): `cyops_utilities.raise_exception` with a clear
   `msg` — fails the run with a readable reason.
3. **User-facing error**: a Manual Input with a single "Close" option showing an error banner
   (Fortinet does this for "alerts from multiple tenants selected").
Also: notification on failed executions (SOAR Framework rule "Notify Failed Playbook Executions").
Use `ignore_errors` only where failure is acceptable — never on remediation steps.

### 6.5 Record uniqueness (Create Record)
| Desired behaviour on duplicate | `collection` | `__replace` |
|---|---|---|
| Fail / stop the run | `/api/3/<module>` | `""` |
| Keep existing, change nothing | `/api/3/upsert/<module>` | `false` |
| Update all fields | `/api/3/upsert/<module>` | `true` |
| Update selected fields only | `/api/3/upsert/<module>` | `true` + `__fieldsToUpdate` |

Uniqueness itself is defined on the module's fields (unique constraint) — upsert needs it.
Indicators: always `/api/3/upsert/indicators` with `operation: Append`.

### 6.6 Linking records
Use `resource.__link: {"indicators": [iris]}` in Update Record (Append) instead of separate link
steps. Link in batches of ≤ 99 per call. Propagate owners/teams to new linked records
(`__link: {"owners": …}`) so RBAC/multi-tenant visibility is preserved.

### 6.7 Human in the loop
- **Approval**: Manual Input `is_approval: true`, assigned to a team (`owner_detail.assignedToTeam`),
  options Approve (primary) / Reject, each routed to a branch. Read result via
  `vars.steps.<name>.approved`, `.message`, `.user`.
- **DecisionBased input with timeout**: `timeout.step_iri` = branch taken automatically if nobody
  responds (Fortinet's phishing approval auto-proceeds after 1 hour). Decide explicitly whether
  timeout = proceed or = stop.
- **Manual Task**: creates a `tasks` record for actions automation cannot do; read `.status`.
- Clean up pending manual inputs when a record is closed (Fortinet: "Manage Closed Alerts – Remove
  Pending Manual Inputs").

### 6.8 Posting comments / audit trail
Robust default: one referenced comment utility playbook whose last step is **Create Record → Comments**
with `content` = rendered HTML and the relationship field set to a plain IRI (`alerts` =
`{{ vars.input.params.record_iri }}` — not a list expression; check the output shows `alerts [1]`).
Do not depend on `cyops_utilities` operations (`no_op`, `make_cyops_request`): that connector can be
missing on an instance; use a Set Variable as the Exit step instead. A standard ITSM comment carries
stage badge, actor, IST time, result, next step, timing and an SLA row.
Alternatively, use the `message` step utility on the Update/Find/Reference step
(`message.content`, `records: <iri>`, type = Comment picklist) — no extra step needed.
HTML badges (`<span class="badge badge-pill" style="background:…">Malicious</span>`) make the
outcome readable at a glance.

### 6.9 Pluggable enrichment / actions (the framework's key idea)
- Each enrichment playbook is tagged by indicator type (`IP_Enrichment`, `URL_Enrichment`,
  `FileHash_Enrichment`…).
- A utility playbook finds active, configured playbooks with that tag (`query_cyops_resource`) and
  stores their IRIs in a Global Variable (`updatemacro`), e.g. `IP_Enrichment_Playbooks_IRIs`.
- The core "Enrich Indicators (Type All)" playbook reads that variable and calls each one in a
  **parallel `for_each` Reference step with `workflowReference: {{vars.item}}` and
  `ignore_errors: true`**, then merges verdicts.
- Every enrichment child returns a uniform contract: `verdict`, `cti_name`, `cti_score`,
  `source_data`, `enrichment_summary`.
Apply the same design to your own extensible processes: dispatcher + tagged plug-ins + uniform output.

### 6.10 Dispatcher by type
"Action (Type All) - Block Indicators" = Decision on indicator type → Reference the type-specific
playbook (Block IP / Domain / URL / File Hash / Email / Isolate Host), with `default` → Do Nothing.
Each child takes the same parameters (`inputIndicatorValue`, `inputIndicatorRecordIRI`,
`inputActionReasons`).

### 6.11 Reference playbook settings
- `apply_async: false` (default) when the parent needs the child's output. `true` only for
  fire-and-forget work (notifications, recomputation) — async output is not available to the parent.
- `pass_input_record: true` only when the child needs `vars.input.records`.
- `pass_parent_env: false` (default) — pass explicit `arguments` instead of leaking all variables.
- Declare child inputs in playbook **Parameters** and document them in the description.

### 6.12 Multi-tenant (MSSP)
Fortinet checks `vars.input.records[0].tenant.isDedicated` and runs enrichment/extraction on the
tenant node when dedicated. Carry `tenant` IRIs through created records; never hard-code a tenant
IRI; block actions that span multiple tenants.

## 7. Jinja cookbook (FortiSOAR-specific filters)

```jinja
{# picklist by name — never hard-code /api/3/picklists/<uuid> #}
{{ "Severity" | picklist("High") }}                       {# full object #}
{{ ("IndicatorReputation" | picklist("Malicious"))["@id"] }}
{{ vars.input.params.indicator_type == "IndicatorType" | picklist("IP Address","itemValue") }}

{# fetch a record by IRI inside Jinja (use sparingly, it is an API call) #}
{{ (vars.alert_iri | fromIRI).severity.itemValue }}
{% set ind = (vars.alert_iri + "/indicators?&__selectFields=reputation") | fromIRI %}

{# list processing #}
{{ vars.steps.Find_Records | json_query('[].reputation.itemValue') }}
{{ vars.result | json_query("[?type != `File` && type != `CVE`]") }}
{{ vars.list | unique | length }}   {{ vars.a | union(vars.b) }}   {{ vars.a | difference(vars.b) }}
{{ vars.items | batch(18) | list }}  {{ vars.nested | flatten(levels=1) }}

{# safe defaults / dual entry #}
{{ vars.input.params.x | ternary(vars.input.params.x, vars.input.records[0].x) }}
{{ vars.value | default('N/A') }}

{# range mapping (score → severity) #}
{{ vars.score | resolveRange({'0': 'Minimal', '1,2,3': 'Low', '4,5,6': 'Medium', '7,8': 'High', '9,10': 'Critical'}) }}

{# type checks, conversions #}
{% if vars.x | type_debug == 'dict' %}…{% endif %}
{{ vars.data | toJSON }}   {{ vars.text | toDict }}   {{ vars.dict | json2html }}
{{ vars.iri | basename }}  {# IRI → UUID #}   {{ vars.iri | iriToLink }}

{# regex #}
{{ vars.headers.to | regex_findall("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+") }}
{{ vars.received[-1] | regex_search('(?:[0-9]{1,3}\.){3}[0-9]{1,3}') }}

{# accumulate into a list inside a loop / Set Variable #}
{% set sd = {} %}{% for i in vars.steps.X %}{% set _ = sd.update(i.source_data) %}{% endfor %}{{ sd }}
{{ vars.unified_iocs.extend(vars.body_iocs) }}
```
Rules: use `itemValue` for picklist comparisons, `@id` for writing picklist fields; prefer
`json_query` over Jinja loops for filtering; keep multi-line Jinja in Set Variable steps, not in
step parameters.

## 8. Naming and documentation conventions

- **Collections:** `NN - Area` (`03 - Enrich`, `04 - Actions`); custom ones continue the scheme
  (`02 - Use Case - <Name>`, `09 - <Org> Custom`). Never edit Fortinet's packs in place — clone
  into your own collection, otherwise upgrades overwrite your changes.
- **Playbooks:** `<Object> - <Action> (<Qualifier>)`, e.g. `Alert - Escalate To Case`,
  `Action - IP Address - Block (Indicator)`, `Enrich Indicators (Type All)`,
  `Case - Set Resolved Date (Post Update)`. Ordered use-case steps get a prefix: `01 -`, `02 -`.
- **Tags:** `#PostCreate`, `#PostUpdate`, `#ManualAction`, `#Subroutine`, plus domain tags
  (`#EDR`, `#Draft`) and plug-in tags (`IP_Enrichment`).
- **Steps:** verb phrases describing intent: `Get IP Reputation`, `Is Malicious`,
  `Update Alert Severity`, `Exit`. Decisions phrased as questions. No `Copy of`, no `Step 3`.
- **Variables:** `snake_case` (or camelCase consistently), suffix by type: `_iri`, `_list`,
  `_count`, `is_`/`has_` for booleans.
- **Description field:** always fill: what it does, trigger, parameters, outputs, dependencies
  (connectors, global variables). Fortinet writes these for every playbook.

## 9. Maturity ladder (Basic → Advanced)

Upgrade one level at a time; each level must be tested before the next.

| Level | Adds | Example (IP enrichment / response) |
|---|---|---|
| **L1 Basic** | Trigger + one action + record update | On Create alert → VirusTotal IP → set reputation |
| **L2 Robust** | Configuration step, filtered trigger, guards, default branches, ignore-error + flag, comment on record | Skip private IPs (`ip_cidr_check`), handle "no reputation" |
| **L3 Modular** | Orchestrator + subroutines with parameters, dual-entry inputs, dispatcher by type | `Enrich Indicators (Type All)` → per-type children |
| **L4 Scalable** | Bulk loops, upsert/dedupe, batch linking, async fan-out, pluggable tags + global vars | Parallel multi-TI enrichment, merged verdict & score |
| **L5 Autonomous** | Scoring/priority weights, correlation of similar alerts, approval-gated remediation with timeout, rollback/unblock path, SLA dates, notifications, metrics | Malicious ≥ threshold → approval → block on firewall → verify → notify → auto-unblock after expiry |

## 10. Design deliverable format

When designing, output:
1. **Flow summary** — one paragraph + the collection/playbook map (which playbook calls which).
2. **Per playbook** — name, collection, tag, trigger (+ exact conditions), parameters, outputs.
3. **Build sheet** — table: `# | Step name | Step type | Key settings / Jinja | Next step(s)`.
4. **Configuration variables** — what the org must fill (domains, subnets, team, thresholds,
   connector config).
5. **Test plan** — mock data / demo record, positive, negative, error and loop tests.
6. **Upgrade path** — what the next maturity level would add.
Default deliverable = a **copy-paste build sheet** (one section per step: type, exact field values,
Jinja in code blocks, branch targets). Offer importable JSON only when asked, and then:
- Ask first for an export of one working playbook from the user's own instance and copy its exact
  wrapper/format; hand-written exports can import partially and leave uuid-conflicting records.
- Warn that a failed import must not simply be retried with the same file (same uuids → "already exists").
- Keep Manual Input and connector steps simple; tell the user which steps to re-select after import.
- Step/route UUIDs and picklist IRIs must be valid on the target instance.

## 11. Review checklist

Run on every exported playbook (severity: 🔴 must fix, 🟠 should fix, 🟢 nice to have).

**Triggers & loops**
- 🔴 On Create/On Update without conditions, or that updates fields in its own trigger condition.
- 🔴 Playbook creates records in the module it triggers on with no guard.
- 🟠 Manual trigger missing `displayConditions` / wrong single-vs-multi record mode.
- 🟠 Relies on On Create firing for bulk-ingested records.

**Structure**
- 🔴 Decision without a `default` branch; dangling steps with no route.
- 🟠 No Configuration step; repeated `vars.input.records[0]…` deep paths.
- 🟠 > 25 steps doing several jobs — split into orchestrator + subroutines.
- 🟠 `vars.steps.<name>` referencing a renamed/missing step.

**Hard-coding (very common, even in vendor content)**
- 🟠 Picklist IRIs (`/api/3/picklists/<uuid>`) in resources/conditions → use `picklist` filter.
- 🟠 Tenant IRIs, team IRIs, user emails, domains, subnets inline → Configuration / Global Vars.
- 🟠 Connector `config` UUID pinned when the default config would do (breaks across instances).
- 🔴 API keys/passwords in step params (e.g. `api_call` headers) → use connector configs / keystore.

**Reliability**
- 🔴 `ignore_errors` on remediation (block/isolate/disable) steps.
- 🟠 Enrichment/TI steps without `ignore_errors` + found-flag handling.
- 🟠 `do_until` with default retries, or no handling when the condition never becomes true.
- 🟠 Wait/Manual Input without timeout branch.
- 🟠 Approval assigned to nobody / no notification.

**Performance**
- 🟠 Sequential loops over large lists where bulk/parallel fits; Create Record per item without bulk.
- 🟠 Find Records without filters or `$limit` (default 30, max 5000) — paginate large sets.
- 🟠 `fromIRI` inside loops (one API call per item).
- 🟢 `apply_async` for fire-and-forget children; `__selectFields` on Find Records.

**Operability**
- 🟠 No comment/status update on the record; no failure notification.
- 🟢 Missing description/parameter docs; inconsistent naming; `debug: true` left on in prod.
- 🟢 Edits made directly inside a Fortinet solution-pack collection.

## 12. Debug procedure

1. **Executed Playbook Logs** (record → Executions, or Automation → Playbook Execution History):
   find the first failed/"Finished with Error" step; read its input and `result`.
2. Check the rendered Jinja: most failures are `None` values (missing field, wrong `vars.steps`
   name, step not yet executed on this branch) or picklist `itemValue` vs `@id` mix-ups.
3. Endless runs → §2 loop rules; deactivate first, then fix conditions.
4. Step-order/parallel-path issues → test with sequential execution; check routes.
5. Connector errors → Connectors → Health Check and the connector config; reproduce the action from
   the connector page with the same params.
6. Slow playbooks → find long steps in the log; apply §11 performance fixes; check worker/queue load.
7. Turn on playbook debug only while reproducing, then disable it.

## 13. Reading an export quickly

Playbook export = zip of `playbooks/<collection>/<playbook>.json` (+ `collection.metadata.json`,
`globalVariables.json`) and solution packs add `playbookBlocks/` (reference blocks). Each playbook
has `name`, `tag`, `parameters`, `triggerStep`, `steps[]` (`name`, `stepType`, `arguments`),
`routes[]`. To summarise one in Python (run with `python3 -I`):

```python
import json, sys
T = {'04d0cf46':'SetVar','12254cf5':'Decision','2597053c':'CreateRec','0109f35d':'Utilities',
     '0bfed618':'Connector','74932bdc':'RefPlaybook','fc04082a':'ManualInput','a19333c2':'Approval',
     'dc6ac63d':'ManualTask','6832e556':'Wait','4c0019b2':'SendEmail','f414d039':'TRIG:Manual',
     'ea155646':'TRIG:OnCreate','9300bf69':'TRIG:OnUpdate','b348f017':'TRIG:Referenced'}
def kind(st):
    u = st.split('/')[-1]
    if u.startswith('b593663d'): return 'FindRec' if u.endswith('770') else 'UpdateRec'
    return T.get(u[:8], u[:8])
d = json.load(open(sys.argv[1]))
print(d['name'], d.get('tag'), d.get('parameters'))
for s in d.get('steps') or d.get('workflowSteps', []):
    a = s.get('arguments') or {}
    flags = [k for k in ('when','for_each','do_until','ignore_errors','apply_async','message') if a.get(k)]
    print(f"  [{kind(s['stepType'])}] {s['name']} {flags}")
```
Then review each step's `arguments` against §11.

## 14. Field lessons (UI build, testing, import)

When the user builds by hand in the UI, state these rules up front — they caused most real errors:
- **Decision condition box: no `{{ }}`** — the UI wraps it (`vars.domain == ''`). Exported JSON stores
  it with `{{ }}`; typing braces in the UI gives `{{ {{ … }} }}` → "expected token".
- Every decision condition needs a target step (else `CS-WF-10`) and a Default.
- Variable and step names are case-sensitive and must match exactly (`confidence` ≠ `Confidence`);
  a misspelt name surfaces later as "dict object has no attribute …". Straight quotes only.
- A Set Variable with an empty value is not created → give a placeholder (`0.0.0.0`, `none`).
- `vars.result` is not in the variable picker — type `{{vars.result}}` in the step's + Variables.
- Hyphenated parameter names need bracket access: `vars.input.params['next-step']`.
- "Rerun From Last Failed Step" replays the old version — after edits, Save Playbook and start a fresh run.
- On Create never fires for alerts that already exist → provide a Manual-trigger variant (or switch the
  trigger to Manual temporarily) to test on an existing alert.
- SLA field names vary per instance → detect keys containing ack/resp + due/date dynamically, or
  confirm names from a `fromIRI` read before writing `ackDate`/`responseDate`.

Semi-automation pattern (proven): intake + TI + triage comment → **Manual Input** (Record Linked to
the alert, Internal Users = SOC team, required Text Area `justification`, response mapping per action,
Escalation 60 min → no-response comment) → per-branch comment → action child (Ignore Error = No) →
close (status, closure notes, ack/response dates). Read the answer as
`vars.steps.<Step_Name>.input.<field>` and verify the path in the first run's OUTPUT.

SIEM data: alerts built from DNS logs may show a public resolver as source and the internal DNS server
as target — block the domain, never the resolver IP; extract the IOC from `sourcedata.associated_events`
attributes when the incident fields lack it; dedup by the indicator, not by the IP pair.

Server-side diagnosis (read-only first): API errors in `/var/log/cyops/cyops-api/prod.log`;
`sealab.workflow_workflow` = execution history, playbook definitions live in `das`; back up with
`sudo -u postgres pg_dump … -f /tmp/…` (postgres cannot write `/root`); never give a DELETE without a
backup and a confirmed row list. A "VM configuration failure" banner at login is a platform issue —
flag it, don't work around it.

## Sources this standard is built on
- SOAR Framework solution pack (collections 01–08 + `playbookBlocks` reference blocks) — export it
  from Content Hub; GitHub `fortinet-fortisoar/solution-pack-soar-framework` holds only its docs.
- Use-case packs on GitHub (`fortinet-fortisoar/solution-pack-*`, `develop` branch, `playbooks/`).
- Connector sample playbooks (`fortinet-fortisoar/connector-*/<name>/playbooks/playbooks.json`).
- FortiSOAR Playbooks Guide (triggers, loops, do-until, Ignore Error, mock output, recursion params).
When a version-specific behaviour matters, check the Playbooks Guide for the user's FortiSOAR version.
---
Copyright (c) 2026 dhaneshwar ([@dhn0x](https://github.com/dhn0x)). Licensed under the MIT License — see [LICENSE](LICENSE).
FortiSOAR and Fortinet are trademarks of Fortinet, Inc. This is a community skill, not an official Fortinet product.
