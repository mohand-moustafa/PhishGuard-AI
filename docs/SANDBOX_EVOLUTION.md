# Safe Browser evolution and validation

## Checkout audit

The starting point was the local `data-process` checkout at `3b68089e2c8be496d0a8f5f8b05313a43c50f942`. The Safe Browser, API, Explorer, guide and tests were already present as uncommitted work. Git also showed existing edits to `.env.example`, `.gitignore`, `requirements.txt` and `README.md`. The audit used the working files, callers, fixtures and test results as well as the project plan. The baseline run passed 106 tests in 41.84 seconds with two Docker checks skipped.

| Area inspected | Verified starting state and integration decision |
| --- | --- |
| Trained models and data | The operational adapter uses fitted URL features, preprocessing and PCA, logistic regression, XGBoost, the stored threshold and SHAP contributions. Test cases exercise stored feature rows and reconstruct the trained probability. The general URL feature extractor and the fitted input definitions have different contracts. The existing trained-input adapter remains the prediction path. |
| Acquisition and isolation | FastAPI admits bounded authenticated jobs through SQLite. Each supervisor runs a child process. A restricted HTTP broker validates destinations and pins its connections. The browser receives an offline archive through stdin. The replay digest alone did not validate the semantics of individual archive entries. |
| Browser and evidence | The existing scanner already sampled pointer receivers and screenshot pixels and ran disposable synthetic probes. A single passive snapshot missed delayed changes. Listener and runtime joins could mix sibling or replaced documents with identical selectors. A synthetic child-frame form submission could yield a critical finding on a parent overlay. |
| Vision and analysis | Tree-sitter, Chromium instrumentation, local OCR, optional YOLO/CLIP, the existing correlator and score dimensions were integrated. The center of an OCR box could associate visible words with the transparent layer above them. Trained optional brand weights were absent locally. |
| API and Explorer | The existing React views, authenticated artifact API, replay records and terminal job states worked. There was no run-to-run behavior comparison, explicit sequence view or checkpoint coverage. Multiple screenshot names often stored identical bytes. |
| Wider repository | Data collection, training notebooks, ML artifacts and existing validation experiments have separate entry points. The extension and several branch/fusion directories are scaffolding on this checkout. The sandbox changes use the working model, browser, API and Explorer paths. |

The phases below followed the dependency order. Capture validation precedes rendering, collection supplies scoped evidence to correlation, and the existing Explorer reads the resulting report.

## Implemented changes

1. **Capture and replay.** Every retained entry must have a canonical permitted URL on the final origin, an accepted status, a bounded canonical Base64 body, and replay-safe headers. The root must be HTML. The broker, validator and renderer share the header allowlist. Response framing, aggregate read limits, attachment refusal, redirect omissions and the rule against reissuing a started GET have regression coverage. Replays validate content before Docker startup and require the original image identity. The original URL model result is reused.
2. **Browser inspection.** Two bounded passive checkpoints record actual elapsed times, frame/document identities and screenshot coordinates. The scanner traverses open shadow roots, qualifies selectors with their host paths and verifies pointer hits through ancestor frames. It compares unique same-document receivers at identical coordinates. Frame navigation starts a new document generation. A transition between observations has two evidence stages. The report makes no claim about the precise time or script that caused it.
3. **Controlled interactions.** The combined budget is 240 region visits and 1,800 hit-test samples, with at most 12 frames, 24 open-root visits and four top-level probes. The early map uses at most 40 region visits and 240 samples. A missing row on a capped early map is unobserved. An eligible control can still be tested if its fresh replay passes early same-coordinate/selector checks and the receiver is checked again before the click. The report records exclusions and incomplete maps. Changed, ambiguous, transformed or unreachable states can limit attribution.
4. **JavaScript and attack sequences.** Static analysis retains syntax locations and document-scoped listener associations. Runtime form-destination changes retain redacted previous/final destinations and mark coalesced mutations. Verified sequences join events on document, frame, phase and action. A destination change must refer to the same submitted form and endpoint in the appropriate observed order. The report identifies collection order, evidence source, uncertainty and whether an operation was observed, inferred or blocked. Sequence stages reference underlying evidence. Risk uses the strongest supported observation per dimension.
5. **Vision and behavioral profiles.** The vision analyzer assigns OCR and contour evidence to geometrically overlapping visible regions and separately records verified covering receivers. The model availability flags distinguish local OCR from optional brand backends. Versioned SHA-256 profiles cover DOM, JavaScript, request destinations, navigation and visual observations. They exclude raw URL queries, event clocks, job IDs and live broker traffic. A changed digest localizes differences to observation groups. A matching digest establishes equivalence only under that summary.
6. **Storage and Explorer.** Duplicate PNGs share a job-local copy. The store checks dimensions, chunk integrity, terminator, static frame count and pixel decodability, with existing logical quotas charged on every screenshot name. The Explorer loads interaction images on expansion, shows sequences with source records and screenshots, filters identical selectors by frame, and displays omissions, coverage, profile comparisons and measurements. Its 8 × 6 viewport grid counts distinct recorded late-checkpoint coordinates per cell. A sampled cell provides evidence at those specific points. The existing API paths and screenshot URLs still serve older records. New fields are additive. Older profiles are unavailable for comparison.

### Changed files in this evolution

| Files | Responsibility |
| --- | --- |
| `src/sandbox/__init__.py`, `isolation_capture.py`, `isolation.py` | Shared header policy, broker, archive validation, container supervision and timings |
| `src/sandbox/browser.py`, `browser_selectors.js`, `browser_inspect.js`, `browser_monitor.js`, `worker.py` | Scoped browser evidence, shadow and frame geometry, checkpoints, runtime observations and measurements |
| `src/sandbox/analysis.py`, `analysis_js.py`, `analysis_vision.py`, new `analysis_profile.py` | Evidence provenance, static rules, visible-owner matching, sequence construction and behavior profiles |
| `src/sandbox/jobs.py`, `store.py` | Phase measurements, replay comparison, validated/deduplicated artifacts and backward-compatible reads |
| `frontend/src/main.jsx`, `frontend/src/style.css` | Extensions to the existing analyst interface |
| `tests/test_sandbox_isolation.py`, `test_sandbox_browser.py`, `test_sandbox_browser_runtime.py`, `test_sandbox_analysis.py`, `test_sandbox_api.py`, `test_sandbox_explorer.py`, new `test_sandbox_profile.py` | Regression and enforcement tests |
| New `tests/fixtures/sandbox/scopes.html`, `dense.html` | Harmless frame, component, timing and sampling controls |
| New `experiments/sandbox_validation/benchmark_fixture.py`, `docs/SAFE_BROWSER.md`, this audit | Local measurement harness and operator documentation |

Files in the table are relative to the directory named at the beginning of each cell. The Git diff against HEAD also contains the uncommitted implementation that was present at the start.

## Verification boundaries

The final full local suite collected **186 tests**. **182 passed, zero failed and four were skipped** in 72.66 seconds. The production React bundle compiled successfully. The Python sources compiled, and `git diff --check` passed. The 22 model-loader warnings included a saved scikit-learn 1.8.0 logistic estimator loaded by 1.9.1 and NumPy/joblib deprecations. The model parity and SHAP reconstruction tests passed in that environment.

The [portable fixture report](../reports/local-sandbox-example/evolution/report.json) records the receiver at viewport position (144, 148) changing from `#reference` to `#late-layer` between 360 and 1,469 ms. It records eight final regions, three frames, two open shadow roots and 39 distinct final viewport positions. The 81 samples include both checkpoints and overlapping regions. The independent dense-page regression verified an eligible static control after the early region cap and skipped an unverified delayed receiver. The accessible checkbox and non-receiving transparent decoration retained their benign classifications.

| Status | Scope |
| --- | --- |
| Exercised locally | Checked-in synthetic HTML in local Chromium, offline request routing, native pointer hits, document navigation, open roots and inaccessible interiors, dense-map limits, accessible controls, credential-form observations, OCR, real saved URL models, SQLite retention, authentication, React production build and authenticated browser-to-API workflow. A real renderer crash during baseline capture raised a scan error, closed its context and allowed a subsequent clean offline replay. |
| Exercised with controlled dependencies | Resolver and socket results for IPv4/IPv6 pinning and redirects, resource omissions/response truncation, archive validation before render, Docker CLI construction and failure handling, and optional brand-model output contracts. A listening loopback fixture received zero broker requests. Real child processes exercised exit, deadline and service-shutdown paths. |
| Skipped here | Four opt-in Linux Docker tests. This workstation had no Docker CLI/Engine or installed WSL distribution. Effective kernel isolation, gVisor compatibility and live container removal require verification on the provisioned analysis host. |
| Not executed | Public website acquisition, hostile-site execution, real brand-model inference, production throughput/load testing and a labeled real-world accuracy study. Fixture scores and heuristic confidence describe evidence in those cases. |
| Not applicable | Training, threshold tuning and deployment were outside this change. |

Deployments must configure their own publicly routed internal CIDRs and egress controls. The broker trusts the local resolver, routing and TLS trust store. The archive digest detects differences from the stored capture metadata. Both are in the same local trust boundary, so integrity also depends on host and database access controls. Timing-dependent pages can vary per replay. Closed shadow roots, late or offscreen interactions, external assets and unsupported frame transforms can leave blind spots. Page-world instrumentation can be altered or suppressed. A real attempt to send synthetic data can be recorded as blocked. The report cannot establish successful credential delivery from this observation.

## Measurements

Three successive `actions.html` assessments shared one local Chromium process. Each assessment used new browser contexts. The first run loaded the model and OCR into the Python process. The other two used warm caches. Both rounds recorded nine final regions and three probes per run. The evolved fixture's small external callback also exercises recorded form-action changes. The timings describe this fixture and machine.

| Measurement | Starting checkout | Evolved checkout |
| --- | ---: | ---: |
| Total wall time, three assessments including browser launch | 16.49 s | 21.98 s |
| Chromium launch | 0.252 s | 0.649 s |
| Warm browser inspection and probes, two-run range | 3.49–3.52 s | 4.64–4.68 s |
| Model inference, cold / warm | 2.72 s / 15 ms | 3.61 s / 15–24 ms |
| Report assembly including vision, cold / warm | 1.56 s / 0.46–0.50 s | 2.03 s / 0.50–0.57 s |
| Passive screenshot capture, annotation and encoding | No separate counter | 113–172 ms |
| Broker discovery and archive assembly from two in-memory fixture responses | No separate counter | 0.30–0.70 ms |
| Peak sampled process-tree working set | 1,038.5 MiB | 1,024.7 MiB |

The additional checkpoint deliberately waits about 1.1 seconds. Warm vision processing took 497–568 ms. Both repeat assessments produced the same five fingerprint sections as the first. The evolved process tree consumed approximately 19.52 sampled CPU-seconds, averaging 0.89 CPU cores over the run. Working-set sums include Python, models, driver and the browser and can count shared pages twice. Sampling at 100 ms can miss short-lived processes. Production jobs use separate processes and can incur cold model costs on each scan.

On the pre-existing calibration example, 11 screenshot names contained three distinct PNG byte streams. Per-job aliases reduce the corresponding stored image payload from 97,355 to 24,627 bytes (74.7%). This measures image bytes and excludes database metadata. All 11 screenshot names and their logical quota charges are preserved. The admission test observed two distinct concurrent claims under five competing claim attempts. Sustained scans per hour require a real worker-host load test.

New full jobs record queue delay, model inference, live capture, container wall time, browser startup, passive screenshot processing, static analysis, vision, correlation and host CPU time when available. Retained replays record a separate validated replay duration and mark model reuse. Worker cgroup CPU time and peak memory are optional counters. Overall host processing ends before the final evidence-store write. The fixture broker measurement excludes sockets, DNS and TLS. Live acquisition latency, Docker replay throughput and container resource consumption were unmeasured on this machine.

Use the [operating guide](SAFE_BROWSER.md) for local build, startup, token and Explorer instructions. To repeat the fixture benchmark, set the same test Chromium environment variable used by pytest and run the following from the project root. The benchmark uses the local test environment's `psutil` and never accepts an arbitrary URL.

```powershell
.\.venv\Scripts\python -m experiments.sandbox_validation.benchmark_fixture
```
