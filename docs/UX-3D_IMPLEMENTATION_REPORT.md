# UX-3D Implementation Report — Security Evidence, Trust & Evaluation

Date: 14-10-2026
Status: COMPLETE

UX-3D does not give the AI autonomous security capabilities.

## 1. Scope

UX-3D makes the framework's security conclusions traceable, explainable and checkable, using only data the system already records. Two chains are now visible end to end:

- **Assessment chain:** Observed evidence → Deterministic finding → Severity → Risk factor → Contribution → Finding risk → Overall risk → AI explanation.
- **Remediation chain:** Baseline assessment → (user remediation) → Verification assessment → Deterministic comparison → Before/after result.

The full auditable lifecycle supported by the system is:

**Observed Evidence → Finding → Context → Risk → Explanation → Remediation → Verification → Comparison**

- Evidence, findings and risk are produced only by the deterministic assessment and risk engines.
- Explanations are written on request from those records.
- Remediation is the backend's recorded text.
- Verification is a new, explicitly confirmed assessment.
- Comparison is the existing deterministic comparison engine.

Out of scope, and not added: tool calling, autonomous agents, RAG, vector databases, background scanning, autonomous remediation, new scanner, risk or comparison engines, and any new navigation item. Primary navigation is still Assistant / Security / History / More.

## 2. Existing architecture reused

| Capability | Existing implementation reused |
|---|---|
| Evidence → finding link | `assessment_findings.evidence_reference` → `assessment_evidence.id` (already in `GET /assessments/{id}`) |
| Finding risk / overall risk | `risk_snapshots` (per finding via `finding_ref`, overall with `finding_ref` NULL), with `factor_contributions` and `context_inputs` |
| Provenance labels | `provenanceOf()` in `detailFormat.ts` (Observed evidence / Configured input / Not assessed or not observed) |
| Before/after | `compareAssessments()` in `lib/assessmentComparison.ts` (gate, risk delta, remaining/new/resolved/not confirmed, coverage rule) |
| Explicit re-run | `ReassessmentPanel` + `createReassessmentFlow` (confirm dialog → existing `POST /assessments`) |
| Issue grouping | `summarizeIssues()` / `issueGroup()` in `lib/securityHome.ts` |
| AI explanation | `POST /assistant/explain` (backend-built context, validator, deterministic fallback, cache) |
| Experiments | `GET /experiments` (already shown on Risk & Research) |
| Full comparison view | History → Compare checks (`AssessmentComparisonResult`) |

All new UI lives inside the existing assessment details. These are shown on Security → Technical details for the latest check, and on History for any check.

## 3. Evidence traceability

There is a new **Security trace** section (`#assessment-trace`) in the assessment details, with one collapsible chain per finding. Findings are ordered most severe first, and the first one is open by default.

1. **Finding**: check ID, title, target:port.
2. **Observed evidence**: the evidence record whose `id` equals `finding.evidence_reference`. It shows check type, result, source, target:port and observed time.
   - If the reference is missing or does not resolve, the view shows exactly: *"Evidence not available for this finding."*
   - Evidence is never inferred from a title, port or source, and never synthesized.
3. **Severity**: the recorded severity, set by the check's deterministic rule.

Real data (latest assessment `4c6fcd59…`): IOT-MQTT-01 → evidence `7eef1385…` `MQTT_ANONYMOUS_CONNECT · ACCEPTED`, source `MQTT_PROBE`, `10.188.244.85:1883`. All 7 findings resolve to recorded evidence (0 "not available").

## 4. Risk traceability

The trace continues:

4. **Risk factor**: the factors the backend links to this finding. Each shows the factor, contribution (`+10 points`), normalized value and basis (provenance badge plus the recorded `source`).
   - The remaining factors of the same risk result are listed under "Other factors in this risk result".
   - Configured factors show their recorded limitation text, and network exposure shows its recorded derivation.
5. **Finding risk**: the finding's own recorded snapshot (score, level, base severity, context score). Informational findings have no snapshot, and the view says so.
6. **Overall risk**: the overall snapshot. When the backend reports that this finding's snapshot is the one used as the overall risk, the view says so.

Real data: IOT-MQTT-01 · HIGH → Authentication Security **+10 points**, normalized value 1, basis *Observed evidence* (`MQTT_PROBE`) → finding risk 70.5 HIGH → overall **70.5 HIGH**, set by this finding (IoT-RISK-v1). This matches the example in the specification.

**Why a backend field was needed.** The finding → risk factor mapping existed only inside `assessment_service._risk_context`; it was not stored and not returned by any API. The frontend could not derive it without guessing: for example, both MQTT findings come from `MQTT_PROBE` evidence but drive different factors. So it must not be guessed. See section 12.

The frontend never recalculates a score. Contributions, normalized values, scores and levels are displayed exactly as recorded, and a test confirms that inconsistent recorded values are shown unchanged.

## 5. AI trust / provenance

Every explanation bubble in the Assistant (AI, AI-unavailable fallback, and rule-based) now has a collapsed **"About this explanation"** panel:

- "Based on your latest security check."
- **Information used**, built from the backend-reported `basis`. Each entry is a recorded section the backend actually put into that explanation's context:
  - ✓ Current risk result
  - ✓ Main risk contributors
  - ✓ Recorded findings
  - ✓ Remediation from the assessment engine
  - ✓ Assessment limitations
- **The AI does not:**
  - ✗ Calculate the risk score
  - ✗ Decide which vulnerabilities exist
  - ✗ Generate security evidence
  - ✗ Run security checks
- **Source label:**
  - "AI explanation: the AI wrote this text from the information above."
  - "Rule-based explanation: the AI was unavailable, so fixed rules wrote this…"
  - "Rule-based explanation: fixed rules wrote this…"

The existing one-line source labels above each answer are unchanged.

Nothing about the model is shown: no prompt, tokens, system policy, chain-of-thought, model name or validator internals. The panel never says the AI scanned, detected or verified anything.

`basis` is computed by the backend from the context it built (`context_basis()`). The model cannot add to it, and the frontend keeps only known names in a fixed order.

Real data:
- "Why is this risky?" → `RISK_RESULT, FINDINGS, LIMITATIONS`
- "How do I fix it?" → adds `REMEDIATION`
- "Explain my risk" → adds `RISK_CONTRIBUTORS`

## 6. Before/after comparison

There is a new **Before and after** section (`#assessment-verification`).

- **Baseline:** the most recent earlier COMPLETE assessment of the same target. **Verification:** the assessment being viewed.
- The baseline is fetched with the existing `GET /assessments/{id}` and compared with the existing `compareAssessments()`.
- **BASELINE / VERIFICATION** panels show the start time, recorded risk and important-issue count.
- The **CHANGE** panel shows:
  - the risk change (the engine's `risk.delta`)
  - Resolved / New / Unchanged / Not confirmed counts
  - a collapsible outcome-per-finding list, also taken from the engine's arrays
- The frontend does not decide resolved, new or improved; the engine's rule (resolved only if the verification run recorded the check as EVALUATED) is stated in the UI.
- "Open full comparison" opens the existing History comparison with the pair preselected.

When there is no earlier completed check, the section shows exactly:

- "No verification comparison is available yet."
- "Run a new security check after remediation to compare the results."
- a **[Run verification check]** button

The button opens the existing re-assessment confirmation dialog (new `requestToken` prop). It never starts a check; the user must still click "Start Re-assessment". Two related states:

- **Incompatible runs** (comparability gate blocks): the same message, plus the gate's reasons.
- **Non-COMPLETE checks:** "Only completed checks can be compared."

Real data:
- Latest `4c6fcd59…` vs `d1fcdc8b…`: risk change 0 points, resolved 0, new 0, unchanged 7, not confirmed 0.
- Oldest completed check `f1ea6cf9…`: no-comparison state.
- INCOMPLETE `8393919a…`: not-complete state.

## 7. Evaluation summary

There is a new **Evaluation summary** section (`#assessment-evaluation`). Every value is counted or read from stored records:

| Card | Contents |
|---|---|
| Assessment | target, status, type, started, completed |
| Coverage | checks evaluated of coverage entries recorded (`metadata.checks_evaluated`, or "Not recorded for this check" for older runs), evidence records, findings |
| Risk | score, level, risk model version (`score_version`), contributor count and recorded contributions |
| Findings | important / minor / informational record counts |
| AI | how explanations are produced and labelled, and what the AI does not do (no per-assessment AI result is invented) |
| Verification | baseline time, verification time, comparison availability |
| Ground truth & experiments | "Ground-truth evaluation dataset is not configured.", plus the existing experiment record(s) from `GET /experiments` with a link to Risk & Research |

Real data: 8 evaluated of 15 recorded coverage entries, 7 evidence, 7 findings, 70.5 HIGH IoT-RISK-v1, 5 contributors (+10, +10, +6, +4.5, +2.5), findings 2 important / 2 minor / 3 informational, comparison available. Experiment: "IoT Context-Aware Dynamic Risk Scoring Experiment", IoT-RISK-v1, COMPLETED.

## 8. Ground-truth handling

- No ground-truth dataset exists, so the UI states "Ground-truth evaluation dataset is not configured." and "Detection accuracy, precision and recall are therefore not reported."
- No precision, recall, F1, accuracy, TP/TN/FP/FN or percentage is shown anywhere. A test checks the rendered summary for metric values.
- No experiment engine was added. Scenarios A–D are not presented as run. Only the experiment record that already exists in the database is listed.

## 9. Security boundary

| # | Boundary | Enforcement / test |
|---|---|---|
| 1 | Traceability uses recorded evidence | joins `evidence_reference` → `evidence.id` only (`traceability.test` B1; backend `test_trace_links_recorded_findings_to_factors_by_backend_rules`) |
| 2 | Frontend does not synthesize evidence | exact "not available" text for missing/dangling refs; no record construction in UX-3D files (B2) |
| 3 | Frontend does not calculate risk | recorded values shown verbatim; static scan for score/weight arithmetic (B3) |
| 4 | Frontend does not calculate comparison results | `verificationView` only maps `compareAssessments` output; no coverage logic in the view (B4) |
| 5–8 | AI cannot alter risk, findings, evidence or remediation | `basis` is backend-computed; unknown names dropped; response has no data fields; explaining leaves records unchanged (B5–B8; `test_model_cannot_add_to_basis`, `test_explaining_never_changes_recorded_data`, `test_response_schema_has_no_data_fields`) |
| 9–10 | AI cannot execute assessments or call security tools | the verification button only opens the confirm step; new views cannot POST; AI layer imports no scanner/probe (B9–B10; existing `test_v_ai_layer_imports_no_scanner_or_probe`) |
| 11 | Browser cannot access Ollama | no model URL/name in UX-3D files (B11); browser run: 0 model requests |
| 12 | No new autonomous AI capability | only two write routes exist (`POST /assessments`, `POST /assistant/explain`); no `/ai/*`, chat, trace, tool or agent routes (`test_no_autonomous_ai_routes_exist`, B12) |

The AI still must not detect vulnerabilities, generate or invent evidence, calculate or change risk, determine severity or resolution, invent remediation, execute assessments, tools or shell commands, access Nmap/MQTT/HTTP/TLS probes, modify records, or make arbitrary network requests. UX-3D adds no path for any of these.

## 10. Files changed

**Backend, added**
- `backend/app/services/risk_trace.py`: read-only trace builder and the shared IoT-RISK-v1 rule sets.
- `backend/tests_phase1/test_risk_trace.py`: 18 tests.
- `backend/tests_assistant/test_assistant_basis.py`: 10 tests.

**Backend, modified**
- `backend/app/schemas/assessment.py`: `RiskTraceFactorOut`, `RiskTraceOut`, `AssessmentDetailOut.risk_trace`.
- `backend/app/services/assessment_queries.py`: attaches `risk_trace` on read.
- `backend/app/services/assessment_service.py`: `_risk_context` uses the shared rule sets (identical sets; behaviour unchanged and tested).
- `backend/app/schemas/assistant.py`: `ExplainBasis`, `AssistantExplainResponse.basis`.
- `backend/app/services/assistant_service.py`: `context_basis()`; `basis` on COMPLETE responses.
- `backend/tests_assistant/test_assistant_explain.py`: exact response-shape expectation now includes `basis`.
- `backend/tests_phase1/test_assessment_metadata.py`: exact field-set guard now includes `risk_trace`.

**Frontend, added**
- `frontend/src/lib/traceability.ts`: trace, summary and verification view models (joins and counts only).
- `frontend/src/lib/traceability.test.ts`: 14 checks.
- `frontend/src/components/assessments/AssessmentTrace.tsx`
- `frontend/src/components/assessments/EvaluationSummary.tsx`
- `frontend/src/components/assessments/VerificationEvaluation.tsx`

**Frontend, modified**
- `frontend/src/api/types.ts`: `RiskTrace`, `RiskTraceFactor`, optional `risk_trace`.
- `frontend/src/api/assistant.ts`: `AssistantExplainBasis`, optional `basis`.
- `frontend/src/lib/assistant/conversation.ts`: validated `basis` on explanation replies and messages.
- `frontend/src/components/assistant/AssistantPage.tsx`: `ExplanationProvenance` panel.
- `frontend/src/components/assessments/AssessmentDetails.tsx`: three new sections, `history` / `onOpenComparison` / `onOpenResearch` props.
- `frontend/src/components/assessments/ReassessmentPanel.tsx`: `requestToken` opens the confirmation step.
- `frontend/src/components/assessments/AssessmentsPage.tsx`
- `frontend/src/components/security/SecurityPage.tsx`
- `frontend/src/App.tsx`: pass history and navigation callbacks.

Not modified: firmware, MQTT collector, database schema, `risk_engine/`, scanner, `.env`. No dependencies were installed and no Alembic migration was run.

## 11. APIs reused

- `GET /api/v1/assessments`: history for baseline selection.
- `GET /api/v1/assessments/{id}`: evidence, findings, snapshots, (new) `risk_trace`, baseline detail.
- `POST /api/v1/assessments`: only through the existing explicit confirm flow; not called during validation.
- `POST /api/v1/assistant/explain`: unchanged request contract.
- `GET /api/v1/experiments`: existing experiment record(s).

## 12. APIs added

**No new endpoint.** Two read-only fields were added to existing responses:

1. **`risk_trace`** on `AssessmentDetailOut`. It is returned by `GET /assessments/{id}`, and by the existing `POST /assessments` response, which uses the same model.
   - **Necessity:** the finding → risk factor link and the origin of the overall risk were not recorded or exposed anywhere, and the frontend cannot derive them without guessing (see section 4).
   - **Properties:**
     - Derived on read, deterministic and side-effect free.
     - Scoped to the requested assessment's own rows.
     - Contains only IDs and rule names, no scores.
     - Uses the same rule constants as `_risk_context`, so it cannot drift from how risk was computed.
     - `null` when there is no overall snapshot or the snapshot version is not IoT-RISK-v1.
   - **Shape:**
     ```
     {score_version, overall_rule: "HIGHEST_FINDING_RISK", overall_finding_refs[],
      factors[{factor, rule: FINDING_TYPE|OPEN_PORT_EVIDENCE|CONFIGURATION, finding_refs[], evidence_refs[]}]}
     ```
   - **Rules:**
     - authentication_security ← findings of type `MQTT_ANONYMOUS_ACCESS`.
     - protocol_security ← `MQTT_WITHOUT_TLS` / `HTTP_PLAINTEXT` / `OUTDATED_TLS_VERSION`.
     - network_exposure ← `NMAP_PORT`/`OPEN` evidence (the scanner records exactly one per open port counted by the model) and the findings that reference it.
     - device_criticality / firmware_security ← configuration.
2. **`basis`** on `AssistantExplainResponse` (COMPLETE answers only). It lists the names of the recorded sections the backend put into the explanation context.
   - **Necessity:** what an explanation was grounded in depends on the request (for example, remediation only for FIX, contributors only for risk). Only the backend knows what it sent.

No `/ai/trace`, `/ai/evidence`, `/ai/risk`, `/ai/compare`, `/chat` or similar route exists (tested).

## 13. Tests

| Suite | Result |
|---|---|
| Backend `pytest tests_assistant tests_phase1 tests_collector` | **149 / 149 passed** (121 existing + 28 new) |
| Frontend checks (10 files) | **181 / 181 passed** (167 existing + 14 new) |
| `npm run build` (`tsc -b && vite build`) | PASS |
| Lint | No lint script exists in `frontend/package.json` |

Two existing exact-shape guard tests were extended by exactly the new fields (`risk_trace`, `basis`). No assertion was removed or loosened.

New frontend checks, all in `traceability.test.ts`:
- **Boundary:** B1–B12.
- **Data integrity:**
  - D1: COMPLETE / INCOMPLETE / FAILED / RUNNING.
  - D2: no findings / important findings; evidence linked / missing; risk snapshot available / unavailable; trace unavailable.
  - D3: comparison available / unavailable / incompatible.
  - D4: AI / deterministic fallback / deterministic sources.
  - D5: no fabricated metrics.
- **Real data (GET only):** a check against the live latest assessment.

New backend tests:
- **Trace:** links by rule; uses IDs, not titles or sources; overall origin; no invented evidence; ID-only schema; unavailable/legacy cases; version equals the risk engine's; `_risk_context` behaviour unchanged across 7 finding-type sets.
- **Basis:** per intent; without risk; model cannot add to it; rule-based no-issue answer; none for non-COMPLETE; records unchanged after explaining; response schema; route inventory.

## 14. Browser validation

Headless Chrome (CDP) at **1920×1080** and **375×812** against the live backend and Vite. 17 steps per viewport, 34 in total.

| Item | Desktop | Mobile |
|---|---|---|
| A. Assessment detail (Security → Technical details) | PASS | PASS |
| B. Evidence traceability | PASS | PASS |
| C. Risk traceability | PASS | PASS |
| D. AI provenance (3 AI answers, panel opened) | PASS | PASS |
| E. Before/after comparison | PASS | PASS |
| F. No-comparison state + Run verification check → confirm → Cancel | PASS | PASS |
| G. Evaluation summary | PASS | PASS |
| H. Assistant still works | PASS | PASS |
| I. UX-3C workflows (check prompt, issue select, why risky, fix, I fixed it, check if fixed, what changed) | PASS | PASS |

Across all 34 steps:
- 0 console errors or warnings, 0 horizontal overflow.
- 0 raw JSON, 0 model internals, 0 prompts or chain-of-thought.
- 0 fake metrics; no invented evidence, findings, risk or comparison.
- **0 assessment POSTs; 0 of 256 browser requests went to Ollama.**

In the UX-3C workflows, the Run buttons were checked but not clicked: no new scans were run just for validation.

## 15. Real-data validation

Only existing records were used. The database was not modified and no scan was run.

- **Latest `4c6fcd59…` (COMPLETE):** full chain for IOT-MQTT-01 as in section 4. All 7 findings resolve to recorded evidence. `risk_trace` links IOT-MQTT-02 to protocol_security, and the 3 NET-01 and 2 NET-06 findings to network_exposure via their `NMAP_PORT/OPEN` evidence.
- **Comparison with `d1fcdc8b…`:** compatible, risk change 0, 7 unchanged.
- **`f1ea6cf9…` (oldest COMPLETE):** no-comparison state. **`8393919a…` (INCOMPLETE):** not-complete state, no findings to trace.
- No FAILED or RUNNING records exist; those states are covered by fixtures in D1.

Live remediation comparison was not demonstrated because no controlled security configuration change was performed. All eight coverage-recorded checks of `10.188.244.85` record the same 70.5 HIGH result.

## 16. Deviations

1. **The comparison engine runs in the frontend.** `compareAssessments()` is the existing, approved deterministic engine in `lib/assessmentComparison.ts`. "Frontend does not calculate comparison results" is implemented as: UX-3D views only render that engine's output and contain no comparison logic (tested).
2. **Baseline selection rule.** The before/after section compares a check with the most recent earlier COMPLETE check of the same target. The Assistant's own workflow pair and the History comparison picker are unchanged.
3. **Two exact-shape guard tests** were extended by the two new documented fields.
4. **Experiments are fetched per details view** (`GET /experiments`, read-only) instead of being passed down from the Risk page.

## 17. Known limitations

- `risk_trace` is derived on read from the current IoT-RISK-v1 rules; it is not a stored historical record. It is only returned for IoT-RISK-v1 snapshots and would need versioning if the rules change.
- When several findings share the highest score, `overall_finding_refs` lists all of them; the backend does not record which one was copied.
- The risk model can count a finding twice (base severity and context). This is the recorded model limitation and is shown in the trace.
- Device criticality and firmware security remain configured inputs.
- No ground-truth dataset, so no detection-quality metrics.
- No real remediation scenario has been recorded (section 15).
- `basis` lists the sections given to the explanation, not which sentences used them.
- In development mode, React StrictMode issues each detail GET twice; production builds do not.

## 18. Academic significance

UX-3D makes each conclusion in the framework auditable:
- A reader can follow any risk statement back through the recorded factor contribution and the deterministic finding to the observed network or protocol evidence. The links are recorded IDs and the backend's own rules, not reconstructed text.
- Explanations are separated from security decisions: the AI only rewords recorded results, says which recorded sections it was given, and states what it does not do.
- Remediation outcomes are judged only by a deterministic comparison of two recorded assessments, with an explicit coverage rule for "resolved".

This supports reproducible, evidence-based reporting of IoT security assessments. It makes no claim that the approach is more accurate or scientifically superior to other methods. No ground-truth evaluation was performed.

## 19. Final recommendation

**APPROVE.** All requested traceability, provenance, before/after and evaluation views are implemented inside the existing details, without new navigation or endpoints. The two read-only response fields are justified and documented. Backend 149/149, frontend 181/181, build PASS, and desktop and mobile browser validation PASS with 0 automatic assessments and 0 browser-to-Ollama requests.

UX-3D does not give the AI autonomous security capabilities.
