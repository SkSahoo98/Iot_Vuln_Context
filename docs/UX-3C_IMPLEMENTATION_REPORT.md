# UX-3C Implementation Report — Assistant Security Workflow

UX-3C does not give the AI autonomous security capabilities.

## 1. Scope

UX-3C turns the existing Assistant into a guided security workflow:

CHECK → RESULT → UNDERSTAND → FIX → VERIFY → COMPARE → NEXT ACTION

It builds on the frozen UX-3A, UX-3B-1 and UX-3B-2 work without redesigning it. The existing pieces are reused as they are: `AssistantContext`, the classifier, the resolver, `actionDestination`, conversation state, the explanation endpoint, the backend AI context builder and fallback, history, re-assessment, the comparison engine and navigation.

Not in scope, and not added: tool calling, autonomous agents, shell access, AI-driven Nmap/MQTT/HTTP/TLS probing, automatic assessment or remediation, background scanning, streaming, speech, long-term memory, RAG, new database tables, server-side workflow state, new AI endpoints, and new assessment, risk or comparison engines.

## 2. Workflow model

The authority model is unchanged:

Deterministic assessment engine → observed evidence → deterministic findings → deterministic IoT risk → AI explanation/guidance → user action → explicit re-assessment → deterministic comparison.

| Step | What the user does | What decides the result |
|---|---|---|
| CHECK | Asks to check, then clicks **Run security check** | Existing `POST /api/v1/assessments` |
| RESULT | Reads the result card | Backend risk snapshot and findings |
| UNDERSTAND | Picks an issue, asks why it's risky | Backend issue data; optional AI explanation |
| FIX | Asks how to fix it | Backend remediation text; optional AI explanation |
| VERIFY | Clicks **Run verification check** | Existing `POST /api/v1/assessments` |
| COMPARE | Asks what changed | Existing `compareAssessments` engine |
| NEXT ACTION | Picks a suggested next step | Fixed follow-up buttons |

Typed or spoken-style wording never starts a check. "I fixed it", "Check if I fixed it", "Check again" and similar phrases only show a prompt containing the explicit Run button.

## 3. Files changed

Backend:
- `backend/app/schemas/assistant.py`: optional `issue` field (catalog check ID pattern) on the existing explain request, allowed only with FIX and EXPLAIN/ISSUES; new `ISSUE_NOT_FOUND` status.
- `backend/app/services/assistant_service.py`: focused single-issue context and tasks, `ISSUE_NOT_FOUND` handling without a model call, focused deterministic fallback, per-issue cache key, stricter answer validation for invented risk levels.
- `backend/tests_assistant/test_assistant_focus.py` (new, 19 tests).

Frontend:
- `frontend/src/lib/assistant/workflow.ts` (new): workflow state type, button definitions, deterministic cards, comparison summary, run-result replies.
- `frontend/src/lib/assistant/conversation.ts`: optional `workflow` dependency; per-intent workflow handling; `runCheck`, `selectIssue`, `openWorkflowAction`; message `card` and `actions`.
- `frontend/src/lib/assistant/intents.ts`: `FIXED` and `COMPARE` intents and new phrases.
- `frontend/src/lib/assistant/resolve.ts`: `FIXED`/`COMPARE` resolution; `workflowDestination` next to `actionDestination`.
- `frontend/src/api/assistant.ts`: optional `issue` in request types; `ISSUE_NOT_FOUND` status.
- `frontend/src/components/assistant/AssistantPage.tsx`: cards, follow-up buttons, running status line, injected `createAssessment`/`fetchAssessment`.
- `frontend/src/App.tsx`: frontend-only workflow state; list reload after a check is created.
- Tests: `frontend/src/lib/assistant/workflow.test.ts` (new); updated `Navigation.test.ts`, `assistant.test.ts`, `conversation.test.ts`, `assessmentComparison.test.ts`.

## 4. Workflow state

Held in `App` state (with a ref for synchronous reads) so it survives leaving the Assistant. Never persisted, never sent to the backend.

| Field | Meaning |
|---|---|
| `activeAssessmentId` | Assessment the conversation is about |
| `activeFindingCheckId` | Catalog check ID of the selected issue |
| `baselineAssessmentId` | BEFORE side of the last check run from the Assistant |
| `latestAssessmentId` | AFTER side; set only when the new check is COMPLETE |
| `stage` | IDLE / CHECK / REVIEW / EXPLAIN / FIX / VERIFY / COMPARE |
| `lastAction` | Last workflow action |
| `running` | `{kind, target}` while an explicitly started check runs |

Without the `workflow` dependency the conversation behaves exactly as in UX-3B (all existing UX-3B tests still pass unchanged apart from one deliberate wording update).

## 5. CHECK

- "Check my IoT network" (with a completed check available) shows: "I'll run a new security check of your authorized IoT target, 10.188.244.85. It starts only when you choose Run security check." with **[Run security check] [Open check form]**. Nothing is requested.
- Without any completed check, the UX-3B behaviour remains: open the check form.
- **Run security check** calls `runCheck("CHECK")`, which uses the existing `createReassessmentFlow` (its shared in-flight guard prevents a second concurrent check) and the existing `createAssessment` (`POST /api/v1/assessments`). The target is the authorized target of the latest completed check; the backend allowlist still applies.
- While it runs: "Running a security check of 10.188.244.85… This can take a minute." No fake progress; the composer stays usable; Run buttons are disabled.
- On completion: "Security check complete." with a RESULT card (Risk: HIGH — 70.5, Important issues: 2, issue titles) and **[Review issues] [Explain my risk] [Summarize results]**. The assessment list reloads once; no polling.
- No second assessment API was created.

## 6. ISSUE

- "What's wrong?" lists the important issues of the latest completed check as selectable choices (deterministic, no AI call).
- Choosing one sets `activeFindingCheckId`, shows an ISSUE card (title, severity, why it matters) and **[Why is this risky?] [How do I fix it?] [Technical details]**.
- **Technical details** opens the existing Security technical view at the findings section; evidence is not duplicated in the Assistant.
- If the selected issue is no longer in the latest check: "That issue isn't in your latest security check anymore." The selection is cleared and the current issues are offered.

## 7. FIX

- Uses the selected issue. With exactly one important issue it is chosen automatically; with several and none selected, the Assistant asks which one ("I'd start with the most important one: …").
- Shows the ISSUE card with the backend's **Recommended fix** (authoritative), then the AI explanation from `POST /api/v1/assistant/explain` `{intent: "FIX", issue}`.
- If the AI is unavailable the backend's recommended fix is still shown; the backend's own fallback is labelled as a standard summary.
- Follow-ups: **[I fixed it] [Check again] [Technical details]**. "I fixed it" only changes the workflow stage and prompts for verification.

## 8. VERIFY

- "I fixed it" → "Great. Run a new security check to verify the change to “…”. Nothing runs until you choose Run verification check." **[Run verification check]**. No request.
- "Check if I fixed it" → "Verification requires a new security check against the same authorized target, 10.188.244.85. …" **[Run verification check]**. No request.
- **Run verification check** runs the same explicit flow, keeps `baselineAssessmentId` (the previous completed check) and records the new check as `latestAssessmentId`, then offers **[See what changed]**.

## 9. COMPARISON

- Uses only the existing frontend comparison engine (`compareAssessments`, `overallSnapshot`) on the two details loaded with the existing `GET /api/v1/assessments/{id}`.
- Shows BEFORE/AFTER risk, and Resolved / New / Still present / Not checked again issue titles.
- If the checks aren't comparable (e.g. different target or catalog version), the Assistant says so and points to the full comparison.
- "What changed?" without a pair: "Run a new security check first so I can compare it with your previous check." **[Run verification check]**. A pair is also treated as out of date if a newer check was run elsewhere.
- **Open full comparison** opens History with the same pair preselected.
- The AI never decides whether an issue is resolved and is not asked to compute differences.

## 10. SUMMARY

- COMPLETE: RESULT card (risk, count, titles) plus the AI summary, with **[Review issues] [Explain my risk] [Verify after fixing]**.
- INCOMPLETE: "The latest security check did not complete, so I can't summarize a current security result. …"
- FAILED: "The latest security check failed, so there isn't a current security result to summarize. …"
- An older assessment is never substituted.

## 11. AI boundary

- The only AI path is the existing `POST /api/v1/assistant/explain`. Allowed requests: EXPLAIN/RISK, EXPLAIN/ISSUES (optional `issue`), FIX (optional `issue`), SUMMARY.
- `issue` is only a catalog check ID. The backend looks it up in its own latest completed assessment; an unknown or informational issue returns `ISSUE_NOT_FOUND` without calling the model.
- Focused prompts contain only that issue (and its remediation for FIX), never the check ID, target, evidence or other issues.
- The backend validator now also rejects answers that assign a different risk level ("makes your risk CRITICAL", "raises the risk to HIGH", …).
- Deterministic cards are rendered above any AI text; AI text never changes cards, selection, risk, findings or remediation.

## 12. Security controls

- Assessments are created only by `runCheck`, which is reachable only from the Run buttons. No classified or typed text can reach it.
- One check at a time (shared in-flight guard plus workflow `running` state).
- The target is always the authorized target of the latest completed check; the backend allowlist remains the authority.
- No new endpoints, no tool calling, no shell or scanner access from the AI, no browser access to the model service.
- Raw backend errors are never shown: refused checks say "The security check wasn't started. Only authorized targets can be checked."; network failures say "The security check couldn't be started. You can try again."; detail-load failures say "I couldn't load the two checks to compare them. You can try again."
- No IDs (assessment UUIDs or check IDs) are displayed.

## 13. Tests

| Suite | Result |
|---|---|
| Backend (`tests_assistant`, `tests_phase1`, `tests_collector`) | 121 passed |
| Frontend (9 files) | 167/167 checks passed |
| UX-3C frontend (`workflow.test.ts`) | 21/21 checks passed |
| `npm run build` | PASS |
| Lint | No lint script in the project; editor diagnostics clean on all edited files |

Security boundary tests (all in `workflow.test.ts`, real API clients with a fetch recorder):

1. No assessment starts without an explicit action (19 phrases × 6 contexts plus every suggested follow-up): PASS
2. "I fixed it" does not POST: PASS
3. "Check if I fixed it" does not POST: PASS
4. Only the Run button creates an assessment, one at a time: PASS
5. Verification preserves the baseline ID: PASS
6. AI cannot alter risk: PASS
7. AI cannot alter findings: PASS
8. AI cannot create remediation: PASS
9. Comparison stays deterministic (no AI call while comparing): PASS
10. No new AI endpoint: PASS
11. No browser request to Ollama: PASS
12. No new scanner/tool access: PASS

Workflow tests A–I cover the check run, issue selection, FIX with and without AI, the fixed/verify prompts, comparison (including fetch failure, incompatible checks and out-of-date pairs), summary of COMPLETE/INCOMPLETE/FAILED, edge states, and rendering (no IDs, no raw JSON, honest running state).

The backend `test_assistant_focus.py` (19 tests) covers the focused context, `ISSUE_NOT_FOUND` without a model call, no fallback to older assessments, rejection of invented risk levels, per-issue caching and 10 invalid-request cases.

## 14. Browser validation

Headless Chrome at 1920×1080 and 375×812 against the running app (backend allowlist: 10.188.244.85; Ollama `qwen3:8b` reached only by the backend).

Final run on the finished code: 15 steps per viewport, 30 in total.

| Workflow | Desktop | Mobile | Notes |
|---|---|---|---|
| A. Check → Run → completion → Review issues | PASS | PASS | Prompt made no request; one POST on the click; result in 14–18 s; Review issues opened Security |
| B. Review issue → Why risky → AI | PASS | PASS | Issue chosen from the list; focused request `{EXPLAIN, ISSUES, issue}`; AI reply in ~36 s below the issue card |
| C. How do I fix it → FIX | PASS | PASS | Backend recommended fix shown, AI explanation below; ~24–26 s |
| D. I fixed it → no assessment request | PASS | PASS | 0 assessment requests; only [Run verification check] offered |
| E. Check if I fixed it → Run verification → comparison | PASS | PASS | Prompt made no request; one POST on the click; See what changed showed BEFORE/AFTER |
| F. What changed → deterministic comparison | PASS | PASS | No AI request; Open full comparison opened History |
| G. Summary | PASS | PASS | RESULT card plus AI summary (~48 s) |

Across all 30 steps:
- Errors: 0. Console errors/warnings and page exceptions: 0.
- Horizontal overflow: none at 1920 or 375 px.
- `POST /api/v1/assessments`: exactly 4, all with `{"target":"10.188.244.85"}`, all from Run button clicks (2 per viewport).
- Explanation requests: only `{EXPLAIN, ISSUES, issue}`, `{FIX, issue}` and `{SUMMARY}`.
- Browser requests to the model service (11434, `/api/generate`, `/api/chat`): 0.
- Replies containing check IDs, assessment IDs, raw JSON or model internals: 0.
- Running state: "Running a security check of 10.188.244.85… This can take a minute." (no fake progress); Run button disabled while running.

An earlier full run before the final layout change (deterministic headline moved above the card) gave the same results.

## 15. Deviations

- **Optional `issue` field on the existing explain endpoint.** Needed so "Why is this risky?" and "How do I fix it?" are about the selected issue. It is a check ID only, validated by pattern and looked up server-side. No new endpoint.
- **"Explain the changes" is replaced by "Summarize the new check".** The comparison engine is frontend-only, and the allowed AI requests have no comparison type. Rather than send comparison data to the AI or add an endpoint, the deterministic comparison text is shown and the AI can summarize the new (AFTER) check.
- **"What's wrong?" is now a deterministic issue list** instead of an AI explanation, so the user can choose an issue. "Why is this risky?" without a selection still uses the UX-3B-2 AI path.
- **CHECK and VERIFY prompt inside the Assistant** (when a completed check exists) instead of navigating to the form. The form remains one click away ([Open check form]).
- **One UX-3B summary wording changed** to the UX-3C text ("The latest security check did not complete…"); its test was updated.
- **`assessmentComparison.test.ts` selection fix.** That test reads live data and assumed the two newest COMPLETE runs predate coverage recording. The real checks run during validation record coverage, so it now selects the newest two runs without recorded coverage, which is what the test's cases describe.
- **Backend answer validator hardened** against invented risk-level statements.

## 16. Known limitations

- Workflow state is in memory: a page reload clears the selected issue and the BEFORE/AFTER pair (the checks themselves are stored as before).
- Starting a check from the Assistant requires at least one completed check, because that is where the authorized target comes from; otherwise the existing check form is used.
- The comparison card lists all non-informational issues (important and minor), so "Still present" can be larger than the important-issue count.
- A check started from the Assistant waits for the synchronous backend request (about 16–19 s in validation); leaving the Assistant does not cancel it and the result is added when it returns.
- AI explanations take roughly 25–55 s on the validation machine; deterministic cards and buttons appear with the reply, and the composer is disabled only while an explanation is being prepared.
- The validated device was not actually changed between checks, so the real-data comparison showed no change; resolved/new handling is covered by the unit tests.

## 17. Final recommendation

UX-3C is complete and ready for review. The Assistant now guides the user from check to comparison while every security decision stays deterministic: checks start only on an explicit click, risk, findings, remediation and comparison come from the backend and the existing engines, and the AI only explains them through the existing endpoint.

Do not continue to UX-3D without a new request. Do not add autonomous AI, tool calling or background scanning.
