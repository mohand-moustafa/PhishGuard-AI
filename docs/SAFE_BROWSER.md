# Safe Browser and Interactive Threat Explorer

The sandbox captures a public web page with a restricted HTTP client, then replays that capture inside a disconnected Chromium container. A click can reveal its receiver, handler, and intended destination while all subsequent HTTP requests are blocked. The report preserves evidence from both phases and identifies its source.

The [evolution audit and validation results](SANDBOX_EVOLUTION.md) describe the current release's evidence semantics, measured costs, file inventory and outstanding deployment checks.

## Local setup

Use Python 3.12, Node 24, and a local Docker Engine running Linux containers with cgroup v2, seccomp, and unprivileged Chromium user namespaces. The image supports amd64 and arm64. Docker Desktop on Windows needs a working Linux backend. The host account running the API needs access to its local Docker daemon. Keep this service on a dedicated analysis machine or VM when handling hostile content.

From the repository root in PowerShell, use the local Docker Desktop daemon and its default local builder. Dependency installation and the initial image build download public packages and the pinned browser base image.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
npm.cmd --prefix frontend ci --no-audit --no-fund
npm.cmd --prefix frontend run build
docker --host npipe:////./pipe/docker_engine buildx build --builder default --load -f Dockerfile.sandbox -t phishguard-browser:local .
```

On Linux, use the virtual environment's `bin/python`, `npm`, and the local daemon's Unix socket. Build with `docker --host unix:///var/run/docker.sock buildx build --builder default --load -f Dockerfile.sandbox -t phishguard-browser:local .`. A rootless daemon may need its own socket location in `PHISHGUARD_DOCKER_SOCKET`. Leave the worker image in that daemon. Scans use `--pull=never`.

Start the analyst service locally. The token stays in the server environment and the Explorer's page memory. To copy it for the local form on Windows, use `Set-Clipboard -Value $env:PHISHGUARD_SANDBOX_TOKEN` in the same shell before starting Uvicorn.

```powershell
$env:PHISHGUARD_SANDBOX_TOKEN = (& .\.venv\Scripts\python -c "import secrets; print(secrets.token_urlsafe(32))")
.\.venv\Scripts\python -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

Open [Interactive Threat Explorer](http://127.0.0.1:8000/explorer/). Enter the access token and a public HTTP(S) URL you are authorized to analyze. **Open report** takes an analysis ID from the same evidence store. The site screenshot is an image. Selecting a box inspects local evidence. Use the DOM layer selector for transparent controls, interceptions, forms, credential destinations, logo candidates, or script activity. **Click receivers** shows sampled coordinates. The side panel connects the region to its handlers, observed requests, behavior, and before/after captures.

## API

All endpoints below require `Authorization: Bearer <token>`. Submit JSON with a single `url` string. A successful submission returns HTTP 202, an `analysis_id`, and the report URL in the response and `Location` header. The report endpoint returns `queued`, `running`, `completed`, `failed`, or `timed_out`. Poll that endpoint until a terminal status. A completed record contains a `report` object. Static Explorer assets and the API schema are public local resources.

| Method | Path under /api/sandbox | Result |
| --- | --- | --- |
| POST | /analyze | Full interactive assessment |
| POST | /interaction-scan | Runs the same full assessment under the interaction-scan mode name |
| POST | /javascript-analysis | Static analysis and passive load-time instrumentation |
| POST | /replay/{analysis_id} | Re-run a retained capture without contacting the site. No request body |
| GET | /report/{analysis_id} | Job state and completed JSON report |
| GET | /screenshot/{analysis_id}?view=viewport | PNG artifact. Use a name from the report's screenshot index |
| GET | /interaction-map/{analysis_id} | Viewport, element geometry, sampled receivers, and actions |
| GET | /behavior-trace/{analysis_id} | Browser instrumentation and CDP observations |
| GET | /network-trace/{analysis_id} | Broker capture, replayed requests, and blocked attempts |

```powershell
$headers = @{ Authorization = "Bearer $env:PHISHGUARD_SANDBOX_TOKEN" }
$payload = @{ url = 'https://example.org/' } | ConvertTo-Json
$job = Invoke-RestMethod http://127.0.0.1:8000/api/sandbox/analyze -Method Post -Headers $headers -ContentType application/json -Body $payload
Invoke-RestMethod ("http://127.0.0.1:8000" + $job.report_url) -Headers $headers
```

The API accepts six submissions per minute for the installation, with eight queued/running jobs and two concurrent scans across processes using the same SQLite file. It limits request bodies to 8 KiB and bounds worker output, per-report JSON, and screenshot bytes. Admission returns HTTP 429 at capacity. The dispatcher commits evidence and job completion atomically. A stale running job becomes timed out after its lease expires. A queued job can survive a restart. Active jobs are interrupted at clean shutdown.

**Replay capture** repeats the browser experiments against the exact retained resource bytes. The service verifies the SHA-256 digest and local Docker image identity before launch, carries forward the original URL model result, and links the new report to its source. The replay network trace covers its own disconnected session. The original report holds the live broker trace. Browser timing, animations, randomness, and changes to the host's optional analysis models can change the observations.

The service retains at most 24 jobs and expires completed evidence after one hour while running. The private default evidence directory is `.sandbox-data/`. Set `PHISHGUARD_SANDBOX_DATA` to change it. SQLite removes expired records logically and can reuse those disk pages. It provides neither encryption at rest nor forensic erasure. Restrict the directory with host permissions. The bearer token grants access to every retained scan. Multi-tenant access controls, TLS termination, and authentication of individual analysts require infrastructure outside this local service.

The private replay archive contains captured page content and resource URLs, including query strings needed to reproduce the page. The API exposes the capture hash, image identity, screenshots, and findings. It has no endpoint for serving archived HTML or scripts. An admitted replay retains its own copy until that job expires.

New reports include a versioned behavior fingerprint. **Behavior fingerprint** shows which observation groups changed on a retained replay. Comparison with an older report that lacks a compatible profile is unavailable. The capture hash identifies archived bytes. The behavior fingerprint summarizes the evidence a particular run observed.

## Execution and network boundaries

| Boundary | Enforcement |
| --- | --- |
| Capture | Read-only HTTP(S) GET, default scheme ports, verified TLS certificates, public IP validation on every connection. All DNS answers must pass. The socket connects to an approved numeric address, verifies the peer, and retains the original host for HTTP and TLS. Redirects repeat these checks. HTTPS downgrades are refused. |
| Network ranges | Denies loopback, local names, non-global and special-use addresses, IPv6 transition ranges and metadata endpoints. Set `PHISHGUARD_DENY_CIDRS` to comma-separated deployment-owned ranges, including publicly numbered internal networks. The broker trusts the host resolver, routing, and firewall. An upstream egress firewall on a dedicated network is needed for policies involving organization-specific routing, proxies, or NAT. |
| Capture budget | Up to five root redirect hops, 48 additional asset candidates, 2 MiB per accepted body, 6 MiB retained and an 8 MiB application-level response-body read budget. The capture process has a 30-second deadline. Root navigation may redirect to another validated public origin. The broker omits redirected assets, records omissions, and skips attachments, partial responses, and compressed bodies. It sends no session cookies or analyst credentials. A public endpoint can change state on GET. Once a GET begins, a failed read ends that request. |
| Browser | Fresh non-root UID/GID 65532, read-only root filesystem, private IPC and network namespaces, no published ports or bind mounts, all capabilities dropped, no-new-privileges, seccomp, private shared memory and size-limited tmpfs. Chromium's own sandbox is enabled. The worker checks for a loopback-only network namespace. Docker receives the archive on stdin and returns evidence on stdout. |
| Resource limits | Docker receives limits of one CPU, 768 MiB RAM, zero swap, 160 processes, 128 MiB shared memory and 160 MiB temporary filesystem. Before reading page input the worker checks effective cgroup v2 CPU, RAM, swap and process limits, UID/GID, capability sets, seccomp mode, no-new-privileges, read-only root and application mounts, direct socket mounts and network interfaces. Unverifiable controls cause startup to fail. The IPC and tmpfs settings also depend on the local Docker daemon honoring its run arguments. A container watchdog, 90-second host worker deadline and 210-second job deadline bound normal execution. Disposal uses automatic removal, bounded explicit removal and a daemon check when removal fails. Daemon and host failure can delay cleanup. |
| Interaction | Disposable context per experiment, empty permissions, service workers blocked, downloads denied, popups closed, synthetic values only. Probe-time network requests are recorded and blocked, including same-origin GET. The browser never receives the API token, a Docker socket, a host profile, or model files. |

Use `PHISHGUARD_SANDBOX_RUNTIME=runsc` on a daemon with gVisor configured, or run the service in a dedicated disposable VM. The host's Docker capability is privileged. A shared-kernel container has residual kernel and browser escape risk. Start-up failures on hosts that disallow Chromium user namespaces should be resolved by configuring the runtime and verifying its effective protections with the live tests. [Playwright Chromium guidance](https://playwright.dev/python/docs/docker#crawling-and-scraping) · [Docker runtime limits](https://docs.docker.com/engine/containers/run/)

Chromium's zygote uses `chroot` inside a nested user namespace during startup. The scanner's seccomp profile passes this syscall to Linux, which checks the caller's capability in its user namespace. The outer worker has zero capabilities. The live kernel test verifies that Linux denies an outer-worker `chroot("/")`, and the separate browser fixture exercises the nested Chromium sandbox.

## Evidence, scoring, and coverage

The local inference adapter uses the saved feature-engineering/PCA pipeline, logistic baseline, XGBoost residual, and saved threshold. TreeSHAP and linear contributions are expressed in PCA components on the log-odds scale. `final_phishing_probability` comes from this trained URL model. Missing registration age follows the training extractor's missing-age behavior. Browser evidence supplies separate 0–100 heuristic scores. Overall risk takes the largest supported dimension or scaled model probability. Repeated reports of the same signal do not compound into a higher probability. Each finding includes evidence references, confidence, severity, and an explanation.

The training artifacts in this checkout use two scikit-learn versions. Tests cover feature parity on stored rows and the prediction/attribution identity. The available 1.9.1 runtime emits a compatibility warning for the 1.8.0 logistic artifact. The operational URL extractor follows the fitted training definitions. Existing datasets, estimators, and thresholds remain in their original locations.

The visual path combines screenshot regions and contrast with DOM geometry and RapidOCR. It reuses the project's OCR text normalization and keyword functions from local Branch-B commit `0d0560d`. Optional brand verification reads only trusted local assets under `PHISHGUARD_BRAND_MODELS`. Supply `logos.onnx` as a raw YOLOv8 detect export at 640×640 with output `[1, 4+C, N]` and `brands.json` in matching class order. Each entry has a `brand` string and `domains` array. Optional `clip/` contains a local Hugging Face CLIP model in safetensors format and its processor, requiring compatible `torch` and `transformers`. Reports expose each backend's availability. A logo on a different host can be legitimate. Optional `PHISHGUARD_FLAGGED_DOMAINS` points to a local newline-separated exact-host reputation list.

Adaptive sampling uses element rectangles, `elementFromPoint`, layer stacks, boundaries, covering regions and screenshot pixels. The scanner takes an early observation, then waits at least 1.1 seconds between checkpoints. Before the later capture it checks for visible content, completed document loading, available images, settled fonts, busy components and a stable viewport. A six-second readiness budget bounds this check. **Original → Initial observation** displays the earlier pixels when the scanner retained a change. The viewport, annotations and final DOM map use the later checkpoint.

The Explorer displays a message beside a partial capture or one that reached its wait limit. The JSON report records the wait time and reasons in `coverage.render_readiness`. If an uncaptured main-frame GET navigation would replace a page that has already painted during initial observation, offline replay answers locally with HTTP 204 to keep the last document. The network trace marks the request as blocked and records `navigation_suppressed`. If the page redirects before the first observed paint, the trace records `navigation_before_paint`. A site that needs this navigation to display results may provide only an intermediate or empty page.

When such a navigation leaves Chromium displaying its internal error document, the worker finishes the passive observation without spending the remaining readiness budget. The Explorer explains why the site preview is unavailable. **View network activity** opens the recorded requests and **Show recorded browser screenshot** reveals the original pixels. New reports mark this case with `vision.image_status = "browser_error_document"` and skip OCR and logo inference on the error page. An ordinary loading timeout can still produce a usable site screenshot.

For a document larger than the viewport, the Explorer opens **Original → Full page**. Scroll the Explorer page to inspect the image or choose **Save full-page PNG** to save its original pixels locally. The DOM overlay and click receiver map use the original viewport coordinates. A local link ending in `/explorer/#report=<analysis_id>` selects the saved report for authenticated opening while it remains in the evidence store.

The worker records the original viewport and interaction map before it scrolls. For a taller or wider document it then captures overlapping sections, waits for visible images to decode and components to settle, and assembles the sections into one PNG. This preserves images a virtualized list removes after they leave the screen. The separate pass has a nine-second observation budget and size limits of 1600 pixels wide, 8192 pixels high and eight million pixels in total. `coverage.full_page_readiness` records the observed document dimensions, saved dimensions, viewports visited, blocked resource types and any clipping. Fixed elements may repeat. Content inside independently scrolling panels, content that loads after the deadline and resources missing from the archive may remain absent.

Static capture recognizes declared responsive images, common lazy image attributes and preload references within the existing same-origin and size limits. The Explorer flags blocked stylesheet, script, image and font requests even on older reports with a usable screenshot. Completed screenshots are stored evidence. A new analysis uses the installed worker, while **Replay capture** requires the image identity recorded with the original report.

**Reconstructed sequences** opens observed stages, source records and uncertainty. Use **Inspect attributed region** to select the receiver. The frame filter distinguishes identical selectors in sibling frames. The browser tests up to four eligible top-level controls in fresh replays. Child-frame and shadow-root interiors receive passive inspection. Cross-origin assets, service-worker content, late events, closed shadow trees, offscreen targets and unvisited states reduce coverage. An offline page can behave differently from a live page. Page hooks may be incomplete or falsified. A blocked form or network attempt establishes an observed operation and destination. Credential delivery and malicious intent require independent evidence.

## Verification

Install the test dependencies into the same virtual environment. The host Chromium path is **only for tests of the checked-in fixtures and trusted analyst interface**. The production scan always requires Docker.

```powershell
.\.venv\Scripts\python -m pip install pytest httpx playwright==1.65.2
$env:PHISHGUARD_FIXTURE_CHROMIUM = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
.\.venv\Scripts\python -m pytest -q
```

With the local image built, set `PHISHGUARD_TEST_DOCKER=1` and run the suite again. Three live scenarios exercise effective privileges, resources, namespace and egress restrictions, plus removal after normal execution, a crash and a watchdog timeout. A fourth test exercises the real Chromium worker. All use local fixtures. The separate host tests cover DNS pinning and redirect decisions, private-process faults, stored-model inference and authenticated UI interaction. For the exact test results and limitations of this workstation, see the [validation record](SANDBOX_EVOLUTION.md).

## Implementation files

| Location | Responsibility |
| --- | --- |
| `Dockerfile.sandbox`, `Dockerfile.sandbox.dockerignore`, `src/sandbox/isolation_seccomp.json`, `isolation_seccomp.LICENSE` | Restricted image build inputs and Chromium syscall policy |
| `src/sandbox/isolation.py`, `isolation_capture.py` | Local Docker supervisor, URL policy, DNS pinning, and HTTP capture |
| `src/sandbox/__init__.py`, `worker.py`, `browser.py`, `browser_selectors.js`, `browser_inspect.js`, `browser_monitor.js` | Disposable Playwright sessions, DOM inspection, coordinate testing and runtime evidence |
| `src/sandbox/analysis.py`, `analysis_features.py`, `analysis_model.py`, `analysis_js.py`, `analysis_vision.py`, `analysis_profile.py`, `src/branch_b_model/text_analysis.py` | Static AST analysis, trained-model adapter, OCR and brand adapters, risk scoring, sequences, behavioral fingerprints and reports |
| `src/api/main.py`, `src/sandbox/jobs.py`, `store.py` | Authenticated API, job supervision, bounded SQLite retention and artifact access |
| `frontend/index.html`, `package.json`, `package-lock.json`, `src/main.jsx`, `src/style.css` | React Explorer, local production build, dependencies and lockfile |
| `tests/test_sandbox_isolation.py`, `test_sandbox_browser.py`, `test_sandbox_browser_runtime.py`, `test_sandbox_analysis.py`, `test_sandbox_api.py`, `test_sandbox_explorer.py` | Offline policy, browser, model, API and UI regression tests |
| `tests/fixtures/sandbox/calibration.html`, `actions.html`, `scopes.html`, `dense.html`, `tests/test_sandbox_profile.py`, `experiments/sandbox_validation/benchmark_fixture.py` | Reviewed synthetic pages, fingerprint regressions and local fixture benchmark |
| `docs/SAFE_BROWSER.md` | Local setup, operator controls, validation and coverage |
| Existing `requirements.txt`, `.env.example`, `.gitignore`, `README.md` | Updated dependencies, configuration examples, local outputs, and entry point |
