import React, {useEffect, useRef, useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

const views = ['Original', 'Annotated', 'DOM overlay', 'Click receivers', 'JavaScript', 'Network'];
const severityNames = ['critical', 'high', 'medium', 'low', 'informational'];
const scoreNames = {
  overall_website_risk: 'Website risk', interaction_risk: 'Interaction risk',
  javascript_risk: 'JavaScript risk', visual_deception: 'Visual deception',
  credential_theft_risk: 'Credential theft',
};
const api = '/api/sandbox';
const display = value => value == null || value === '' ? '—'
  : typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value);
const human = value => display(value).replaceAll('_', ' ');
const severity = value => severityNames.includes(String(value).toLowerCase()) ? String(value).toLowerCase() : 'informational';

async function request(path, token, options = {}) {
  const response = await fetch(path, {...options, headers: {
    Authorization: 'Bearer ' + token, ...(options.body && {'Content-Type': 'application/json'}),
  }, cache: 'no-store', redirect: 'error'});
  if (!response.ok) {
    const details = await response.json().catch(() => ({}));
    throw new Error(typeof details.detail === 'string' ? details.detail : 'Request failed (' + response.status + ').');
  }
  return response;
}

function Capture({job, token, imageKey, alt = 'Captured website, ' + human(imageKey), allowDownload = false, children}) {
  const [source, setSource] = useState('');
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    let objectUrl;
    setSource(''); setError('');
    request(api + '/screenshot/' + job + '?view=' + encodeURIComponent(imageKey), token, {signal: controller.signal})
      .then(response => response.blob()).then(async blob => {
        if (controller.signal.aborted) return;
        objectUrl = URL.createObjectURL(blob);
        const image = new Image();
        image.src = objectUrl;
        try {
          await image.decode();
        } catch {
          throw new Error('The screenshot could not be decoded.');
        }
        if (!controller.signal.aborted) setSource(objectUrl);
      }).catch(reason => { if (!controller.signal.aborted) setError(reason.message); });
    return () => { controller.abort(); if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [job, token, imageKey]);
  return source ? <>{allowDownload && <a className="saveCapture" href={source}
    download={job + '-' + imageKey + '.png'}>Save full-page PNG</a>}
    <div className="capture"><img src={source} alt={alt} />{children}</div></>
    : <p className="empty" role="status">{error || 'Loading capture…'}</p>;
}

function unavailableSiteCapture(report) {
  const readiness = report.coverage?.render_readiness;
  if (!readiness?.browser_error_document && !report.final_url?.startsWith('chrome-error:')) return null;
  if (!readiness && report.regions.length) return null;
  const blocked = report.network.filter(event => event.blocked && event.navigation &&
    event.frame_key === 'main' && !event.action_id);
  const beforePaint = blocked.filter(event => event.navigation_before_paint);
  if (!blocked.length && !readiness?.prepaint_navigations) return null;
  const attempts = beforePaint.length ? beforePaint : blocked;
  return {beforePaint: Boolean(beforePaint.length || readiness?.prepaint_navigations),
    destination: attempts.length === 1 ? attempts[0].url : null};
}

function hasLargerCapture(report) {
  const coverage = report.coverage || {};
  return report.screenshots.full_page && (coverage.capture_height > report.viewport.height ||
    coverage.capture_width > report.viewport.width);
}

function CaptureReadiness({report, fullPage}) {
  const coverage = report.coverage || {};
  const readiness = (fullPage && coverage.full_page_readiness) || coverage.render_readiness;
  const clipped = fullPage && coverage.full_page_clipped;
  // Older reports have the underlying request evidence but no readiness counters.
  const blocked = readiness?.blocked_resources || {};
  const assetTypes = ['stylesheet', 'script', 'image', 'font'];
  const missing = assetTypes.filter(type => blocked[type] || report.network.some(event =>
    event.blocked && !event.action_id && event.resource_type === type));
  if (!clipped && !missing.length && !['timed_out', 'partial'].includes(readiness?.status)) return null;
  const messages = {
    no_visible_content: 'The sampled viewport appeared blank.',
    pending_images: 'Visible images were still loading.', failed_images: 'Some visible images failed to load.',
    fonts_loading: 'Fonts were still loading.', document_loading: 'The document was still loading.',
    busy_components: 'Some components were still marked as busy.', viewport_changing: 'The viewport was still changing.',
    inspection_limited: 'Only part of the viewport could be assessed.', inspection_unavailable: 'Viewport inspection was unavailable.',
    navigation_suppressed: 'Offline replay kept the captured page when it blocked a navigation.',
    navigation_before_paint: 'The page tried to open an uncaptured document before any content appeared.',
    browser_error_document: 'Chromium displayed its own error page.',
    scan_budget: 'The full-page scan reached its observation budget.',
    navigation_changed: 'The document changed during full-page capture.',
    scroll_unstable: 'The page moved while a section was being captured.',
    scroll_unreachable: 'Chromium could not scroll to the next section.',
    scroll_navigation_blocked: 'Scrolling triggered a blocked navigation.',
    artifact_budget: 'The saved area was reduced to fit the image size limit.',
    viewport_fallback: 'Only the original viewport was available.',
  };
  const reasons = (readiness?.reasons || []).map(code => messages[code]).filter(Boolean);
  if (missing.length) {
    reasons.push('Offline replay blocked requests for ' + missing.map(type => type + 's').join(', ') + '.');
    const omissions = report.capture?.omissions || {};
    if (omissions['Response exceeds the capture budget']) reasons.push('Some resources exceeded the archive size limit.');
    if (omissions['Cross-origin resource declined']) reasons.push('The archive also omitted resources from other origins.');
  }
  if (clipped) {
    const measured = coverage.full_page_readiness;
    reasons.push(measured?.document_width && measured.document_height
      ? 'The measured document was ' + measured.document_width + ' × ' + measured.document_height + ' pixels.'
      : 'The saved image covers only part of the document.');
  }
  return <p className="captureNotice" role="note"><strong>{readiness?.status === 'timed_out'
    ? 'Capture wait limit reached.' : 'Partial page capture.'}</strong>{' '}{reasons.join(' ')}</p>;
}

function Disclosure({label, children}) {
  const [open, setOpen] = useState(false);
  return <details onToggle={e => setOpen(e.currentTarget.open)}><summary>{label}</summary>
    {open && children()}</details>;
}

function Records({items = [], empty = 'No observations recorded.'}) {
  if (!items?.length) return <p className="muted">{empty}</p>;
  return <ol className="records">{items.map((item, index) => {
    if (typeof item !== 'object' || !item) return <li key={index}>{display(item)}</li>;
    return <li key={index}><Disclosure label={<>
      <strong>{human(item.rule_id || item.type || item.title || item.kind || item.method || 'Observation')}</strong>
      <span>{item.evidence_status && human(item.evidence_status)+' · '}
        {display(item.explanation || item.url || item.detail || item.selector || item.timestamp || item.source || '')}</span>
    </>}>{()=> <pre>{display(item)}</pre>}</Disclosure></li>;
  })}</ol>;
}

function Properties({values}) {
  return <dl>{Object.entries(values).map(([name, value]) =>
    <React.Fragment key={name}><dt>{name}</dt><dd>{display(value)}</dd></React.Fragment>)}</dl>;
}

function RegionDetail({region, report, record, token}) {
  const actions = report.interactions.filter(action => action.element_id === region.id);
  const related = event => event.element_id === region.id;
  const findings = report.findings.filter(f => f.element_id === region.id);
  return <aside className="detail">
    <div className="sectionTitle"><h3>Region evidence</h3><span className={'level ' + severity(region.severity)}>{severity(region.severity)}</span></div>
    <p className="selector">{region.selector}</p>
    <p>{region.explanation || findings[0]?.explanation || human(region.classification)}</p>
    <Properties values={{Tag: region.tag, Bounds: region.bbox, Frame: region.frame_key ?? region.frame,
      Document: region.document_id, 'Shadow hosts': region.shadow_path, Classification: human(region.classification),
      Confidence: region.confidence, 'Risk score': region.risk_score ?? findings[0]?.score,
      'Confirmed mechanism': human(region.confirmed_mechanism),
      'Expected target': region.expected_target, 'Click receiver': region.actual_receiver,
      'Displayed text': region.visible_text, Destination: region.destination, 'Expected destination': region.expected_destination,
      'Computed CSS': region.css, Handlers: region.handlers, 'Handler locations': region.handler_locations}} />
    <h4>Detection evidence</h4><Records items={[...(region.evidence || []), ...findings]}/>
    <h4>JavaScript findings</h4><Records items={report.javascript_findings.filter(f => related(f) || f.element_ids?.includes(region.id))}/>
    <h4>Network & redirects</h4><Records items={report.network.filter(related)}/>
    <h4>Behavior timeline</h4><Records items={report.behavior.filter(related)}/>
    {actions.map(action => <Disclosure key={action.id} label={'Interaction '+action.id}>{()=> <>
      <pre>{display(action)}</pre>
      {[action.before, action.after].filter(key => key && report.screenshots[key]).map(key =>
        <figure key={key}><figcaption>{human(key)}</figcaption><Capture job={record.analysis_id} imageKey={key} token={token}/></figure>)}
    </>}</Disclosure>)}
  </aside>;
}

function Canvas({report, record, token, selected, select, view, chooseBrand, openNetwork}) {
  const {width, height} = report.viewport;
  const isMap = ['DOM overlay', 'Click receivers'].includes(view);
  const [scale, setScale] = useState(() => hasLargerCapture(report) ? 'full_page' : 'viewport');
  const [layer, setLayer] = useState('All regions');
  const imageKey = view === 'Annotated' ? 'annotated' : view === 'Original' ? scale : 'viewport';
  const fullPage = imageKey === 'full_page';
  const coverage = report.coverage || {};
  const extent = fullPage ? (coverage.full_page_clipped ? 'captured area' : 'full page') : 'viewport';
  const dimensions = fullPage ? [coverage.capture_width, coverage.capture_height] : [width, height];
  const unavailable = imageKey !== 'initial' && unavailableSiteCapture(report);
  const rawImageKey = imageKey === 'full_page' ? 'full_page' : 'viewport';
  const brandCandidates = (report.vision.brands || []).filter(b => b.domain_mismatch);
  const behavioral = new Set(report.behavior.filter(e => e.action_id).map(e => e.element_id));
  const accepts = r => {
    switch (layer) {
      case 'Transparent elements': return r.hidden;
      case 'Interceptions': return r.intercepts?.length || r.covered_by?.length;
      case 'Credential destinations': return r.credential && r.destination;
      case 'Forms': return r.tag === 'form';
      case 'JavaScript activity': return r.handlers?.length || behavioral.has(r.id);
      case 'Brand candidates': return false;
      default: return true;
    }
  };
  return <div>
    <div className="canvasHeader"><span>{dimensions.every(Number.isFinite) && dimensions.join(' × ') + ' '}{extent}</span>
      {!unavailable && view === 'DOM overlay' && <select aria-label="DOM overlay layer" value={layer} onChange={e=>setLayer(e.target.value)}>
        {['All regions','Transparent elements','Interceptions','Forms','Credential destinations','Brand candidates','JavaScript activity'].map(item=><option key={item}>{item}</option>)}</select>}
      {view === 'Original' && <select aria-label="Screenshot extent" value={scale} onChange={e => setScale(e.target.value)}>
        <option value="viewport">Viewport</option>{report.screenshots.full_page && <option value="full_page">Full page</option>}
        {report.screenshots.initial && <option value="initial">Initial observation</option>}</select>}</div>
    {unavailable ? <section className="unavailableCapture" aria-label="Website screenshot unavailable">
      <h3>Website screenshot unavailable</h3>
      <p>{unavailable.beforePaint
        ? 'The page requested another document before displaying any content. That document was missing from the offline capture.'
        : 'Offline replay blocked a page navigation. Chromium recorded its error page.'}</p>
      {unavailable.destination && <p>Attempted destination <code>{unavailable.destination}</code></p>}
      <button type="button" className="secondary" onClick={openNetwork}>View network activity</button>
      {report.screenshots[rawImageKey] && <Disclosure key={rawImageKey} label="Show recorded browser screenshot">{()=>
        <Capture job={record.analysis_id} token={token} imageKey={rawImageKey}
          alt={'Recorded Chromium error page, ' + human(rawImageKey)}/>}</Disclosure>}
    </section> : <>
    {imageKey !== 'initial' && <CaptureReadiness report={report} fullPage={fullPage}/>}
    <div className={fullPage ? 'canvas fullPageCanvas' : 'canvas'}>{report.screenshots[imageKey] ?
      <Capture key={imageKey} job={record.analysis_id} token={token} imageKey={imageKey} allowDownload={fullPage}>
      {isMap && width > 0 && height > 0 && report.regions.filter(r=>view !== 'DOM overlay' || accepts(r))
        .sort((a,b)=>(a.risk_score || 0)-(b.risk_score || 0)).map(r => {
        if (!r.bbox) return null;
        const {x,y,width:w,height:h} = r.bbox;
        if (w <= 0 || h <= 0 || x+w <= 0 || y+h <= 0 || x >= width || y >= height) return null;
        if (view === 'Click receivers') return (r.points || []).map((point, i) =>
          <button type="button" key={r.id + '-' + i} title={r.selector + ' · ' + display(point.receiver || point.actual_receiver)}
            aria-label={'Inspect sampled click receiver for ' + r.selector} className={'point ' + severity(r.severity)}
            style={{left: (point.x/width*100)+'%', top: (point.y/height*100)+'%'}} onClick={() => select(r.id)}/>);
        return <button key={r.id} title={r.selector} aria-label={'Inspect ' + r.selector}
          className={'box ' + severity(r.severity) + (r.id === selected ? ' chosen' : '')}
          style={{left:(Math.max(0,x)/width*100)+'%',top:(Math.max(0,y)/height*100)+'%',
            width:((Math.min(width,x+w)-Math.max(0,x))/width*100)+'%',height:((Math.min(height,y+h)-Math.max(0,y))/height*100)+'%'}}
          onClick={() => select(r.id)}/>;
      })}
      {view==='DOM overlay' && ['All regions','Brand candidates'].includes(layer) && brandCandidates.map((b,i)=>
        <button key={b.id || i} title={b.brand + ' logo candidate'} aria-label={'Inspect logo candidate ' + b.brand}
          className="box brandBox medium" style={{left:(b.bbox.x/width*100)+'%',top:(b.bbox.y/height*100)+'%',
            width:(b.bbox.width/width*100)+'%',height:(b.bbox.height/height*100)+'%'}} onClick={()=>chooseBrand(b)}/>)}
    </Capture> : <p className="empty">This capture is unavailable.</p>}</div>
    </>}
  </div>;
}

function Sequences({report, record, token, inspect}) {
  const evidence = new Map();
  for (const group of [report.regions, report.behavior, report.network, report.javascript_findings,
                        report.findings, report.interactions, report.vision?.ocr_lines, report.vision?.brands,
                        report.passive_changes?.changes]) {
    for (const item of group || []) if (item.id) evidence.set(item.id, item);
  }
  return <div className="sequences">{report.attack_sequences.map(sequence => <article key={sequence.id}>
    <div className="sectionTitle"><h4>{sequence.title}</h4><span className={'level '+severity(sequence.severity)}>{sequence.severity}</span></div>
    <p>{human(sequence.attribution)} · {human(sequence.evidence_status)} · Mechanism confidence {display(sequence.confidence)}</p>
    <ol>{sequence.stages.map((stage, i) => <li key={i}><strong>{stage.label}</strong>
      <div className="muted">{(stage.provenance || []).join(', ')} {stage.timestamp && <time>{stage.timestamp}</time>}
        {Number.isFinite(stage.elapsed_ms) && ' · '+stage.elapsed_ms+' ms'}</div>
      <Disclosure label={'Evidence '+stage.evidence_ids.join(', ')}>{()=> <Records
        items={stage.evidence_ids.map(id=>evidence.get(id) || id)}/>}</Disclosure>
      {stage.screenshot && report.screenshots[stage.screenshot] && <Disclosure label="View checkpoint screenshot">{()=>
        <Capture job={record.analysis_id} token={token} imageKey={stage.screenshot}/>}</Disclosure>}
    </li>)}</ol>
    {(sequence.uncertainty || []).map((reason,i)=><p key={i} className="muted">{reason}</p>)}
    {sequence.element_id && <button className="secondary" onClick={()=>inspect(sequence.element_id)}>Inspect attributed region</button>}
  </article>)}</div>;
}

function Coverage({report, inspect}) {
  const c = report.coverage || {};
  const passive = report.passive_changes;
  const grid = c.viewport_sampling;
  const tested = report.interactions.filter(a=>a.status==='tested').length;
  return <>
    <Properties values={{'Inspected frames':c.frames_scanned, 'Sampled regions':report.regions.length,
      'Hit-test points':c.samples, 'Open shadow roots inspected':c.open_shadow_roots,
      'Completed probes':tested, 'Full page clipped':c.full_page_clipped,
      'Captured resources':report.capture?.resource_count, 'Capture omissions':report.capture?.omissions,
      'Remaining resource candidates':report.capture?.remaining_candidates,
      'Active probe scope':c.active_scope, 'Dropped runtime events':c.dropped_events}}/>
    {grid && <><h4>Viewport sampling</h4>
      <p>{grid.distinct_positions} distinct positions in the final viewport. Empty cells had no recorded sample.</p>
      <table className="sampleGrid" aria-label="Counts of sampled coordinates, from top left to bottom right"><tbody>
        {grid.cells.map((row,y)=><tr key={y}>{row.map((n,x)=><td key={x} className={n ? 'sampled' : ''}
          title={`Row ${y+1}, column ${x+1}: ${n} distinct positions`}>{n}</td>)}</tr>)}</tbody></table>
      <p>{grid.regions_without_viewport_samples} regions had no in-viewport sample.</p></>}
    {passive && <><h4>Passive checkpoints</h4>
      <p>{display(passive.early_ms)} ms to {display(passive.late_ms)} ms · {passive.changes.length} recorded changes</p>
      <Properties values={{'Probe exclusions':passive.probe_exclusions,
        'Candidates requiring early replay verification':passive.uncompared_early_replay_candidates}}/>
      {passive.changes.map((change,i)=><div className="checkpoint" key={i}>
        <strong>{human(change.type)}</strong> <code>{change.selector}</code>
        {change.region_id && <button className="secondary" onClick={()=>inspect(change.region_id)}>Inspect change</button>}
        <Properties values={{'Earlier receiver':change.before_receiver, 'Later receiver':change.after_receiver,
          'Frame':change.frame_key}}/></div>)}
      {passive.truncated && <p>Observation limits reduced checkpoint coverage.</p>}</>}
    <Records items={c.warnings} empty=""/>
    <Disclosure label="Coverage metadata">{()=> <pre>{display(c)}</pre>}</Disclosure>
  </>;
}

function Workspace({record, token, replay, busy}) {
  const r = record.report;
  const [view, setView] = useState(() => hasLargerCapture(r) ? 'Original' : 'DOM overlay');
  const networkTab = useRef(null);
  const [selected, select] = useState(r.regions[0]?.id);
  const [brand, chooseBrand] = useState(null);
  const choose = id => {chooseBrand(null); select(id);};
  const inspect = id => {
    choose(id); setView('DOM overlay');
    document.querySelector('.workbench')?.scrollIntoView({block:'start'});
  };
  const [filter, setFilter] = useState('all');
  const [frame, setFrame] = useState('all');
  const frames = [...new Set(r.regions.map(item=>item.frame_key).filter(Boolean))];
  const region = r.regions.find(item => item.id === selected);
  return <>
    <div className="reportTitle"><div><span className="kicker">Completed analysis</span><h2>{record.url}</h2>
      {r.capture?.replayed_from && <p>Replayed from <code>{r.capture.replayed_from}</code></p>}</div>
      {r.replay_available && <button type="button" className="secondary" disabled={busy} onClick={replay}>
        {busy ? 'Starting replay…' : 'Replay capture'}</button>}
      <span className="mono">{record.analysis_id.slice(0,8)}</span></div>
    <div className="scores">{Object.entries(scoreNames).map(([key, label]) =>
      <div key={key}><span>{label}</span><strong>{display(r.scores[key])}<small> / 100</small></strong></div>)}</div>
    <div className="workbench"><section className="observations"><div className="tabs" aria-label="Evidence views">
      {views.map(v => <button key={v} ref={v === 'Network' ? networkTab : null}
        aria-pressed={view===v} onClick={() => setView(v)}>{v}</button>)}</div>
      {view === 'JavaScript' ? <div className="pad"><h3>Static findings</h3><Records items={r.javascript_findings}/>
        <h3>Runtime behavior</h3><Records items={r.behavior}/></div>
      : view === 'Network' ? <div className="pad"><h3>Network activity</h3><Records items={r.network}/></div>
      : <Canvas report={r} record={record} token={token} view={view} selected={selected} select={choose} chooseBrand={chooseBrand}
          openNetwork={() => {setView('Network'); networkTab.current.focus();}}/>}
      <div className="pad"><div className="sectionTitle"><h3>Interaction regions <small>{r.regions.length}</small></h3>
        {frames.length>1 && <select aria-label="Filter by frame" value={frame} onChange={e=>setFrame(e.target.value)}>
          <option value="all">All frames</option>{frames.map(key=><option key={key}>{key}</option>)}</select>}
        <select aria-label="Filter by severity" value={filter} onChange={e=>setFilter(e.target.value)}>
          <option value="all">All severities</option>{severityNames.map(s=><option key={s}>{s}</option>)}</select></div>
        <div className="regionList">{r.regions.filter(item=>(frame==='all' || item.frame_key===frame) &&
          (filter==='all' || severity(item.severity)===filter)).map(item=>
          <button key={item.id} aria-pressed={item.id===selected && !brand} onClick={()=>choose(item.id)}>
            <i className={'dot '+severity(item.severity)}></i><code>{item.selector}</code><span>{human(item.classification)}</span></button>)}
          {!r.regions.length && <p className="muted">No interaction regions recorded.</p>}</div>
      </div></section>
      {brand ? <aside className="detail"><h3>Logo evidence</h3>
        <Properties values={{Brand:brand.brand,'YOLO confidence':brand.confidence,'CLIP similarity':brand.clip_similarity,
          'Outside registered domains':brand.domain_mismatch,Bounds:brand.bbox}}/>
        {(brand.element_ids || []).map(id=><button key={id} className="secondary" onClick={()=>choose(id)}>Inspect {id}</button>)}
      </aside> : region ? <RegionDetail region={region} report={r} record={record} token={token}/> :
        <aside className="detail"><h3>Region evidence</h3><p className="muted">Select a detected region to inspect its evidence.</p></aside>}</div>
    <div className="summary"><h3>Security report</h3>
      <details open><summary>Correlated findings</summary><Records items={r.findings}/></details>
      {!!r.attack_sequences?.length && <Disclosure label={'Reconstructed sequences ('+r.attack_sequences.length+')'}>
        {()=> <Sequences report={r} record={record} token={token} inspect={inspect}/>}</Disclosure>}
      <details><summary>Model prediction & explanation</summary>
        <Properties values={{'Phishing probability':r.final_phishing_probability,Model:r.existing_model_prediction,
          ...(r.model_evidence && {'Evidence status':human(r.model_evidence.evidence_status)})}}/></details>
      <details><summary>Visual and brand evidence</summary><pre>{display(r.vision)}</pre></details>
      <Disclosure label="Evidence timeline">{()=> <Records items={r.evidence_timeline}/>}</Disclosure>
      <details><summary>Recommended mitigation</summary><Records items={r.mitigations}/></details>
      <Disclosure label="Capture coverage">{()=> <Coverage report={r} inspect={inspect}/>}</Disclosure>
      {r.behavior_profile && <Disclosure label="Behavior fingerprint">{()=> <>
        <Properties values={{'SHA-256':r.behavior_profile.digest,'Profile version':r.behavior_profile.version,
          ...(r.replay_comparison && {'Compared with source':r.replay_comparison.status,
            'Changed sections':r.replay_comparison.changed_sections})}}/>
        <p className="muted">The fingerprint summarizes the DOM, scripts, browser requests, navigation and visual observations in this scan.</p>
        <Properties values={Object.fromEntries(Object.entries(r.behavior_profile.sections).map(([k,v])=>[human(k),v]))}/>
      </>}</Disclosure>}
      {r.performance && <Disclosure label="Analysis measurements">{()=> <Properties values={Object.fromEntries(
        Object.entries(r.performance).map(([key,value])=>[human(key),value]))}/>}</Disclosure>}
    </div>
  </>;
}

function InteractiveThreatExplorer() {
  const savedReport = /^#report=([a-f0-9]{32})$/i.exec(window.location.hash)?.[1] || '';
  const [task, setTask] = useState(savedReport ? 'open' : 'scan');
  const [url, setUrl] = useState('');
  const [id, setId] = useState(savedReport);
  const [token, setToken] = useState(() => {
    try {
      return localStorage.getItem('phishguard_sandbox_token') || 'phishguard-safe-container-token-2026';
    } catch (_) {
      return 'phishguard-safe-container-token-2026';
    }
  });
  const [mode, setMode] = useState('analyze');
  const [record, setRecord] = useState(null);
  const [active, setActive] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(true);
  useEffect(() => {
    if (!active) return;
    const controller = new AbortController();
    let timer;
    async function poll() {
      try {
        const response = await request(api+'/report/'+active.id, active.token, {signal:controller.signal});
        const data = await response.json();
        if (controller.signal.aborted) return;
        setRecord(data);
        if (['queued','running'].includes(data.status)) timer = setTimeout(poll, 1200);
        else setBusy(false);
      } catch (e) {
        if (!controller.signal.aborted) { setError(e.message); setBusy(false); setEditing(true); }
      }
    }
    poll();
    return () => {clearTimeout(timer); controller.abort();};
  }, [active]);
  async function submit(e) {
    e.preventDefault();
    setError(''); setBusy(true); setActive(null); setRecord(null);
    try {
      let analysisId = id.trim();
      if (task === 'scan') {
        const response = await request(api+'/'+mode, token, {method:'POST',body:JSON.stringify({url:url.trim()})});
        analysisId = (await response.json()).analysis_id;
      }
      setId(analysisId); setActive({id:analysisId,token}); setEditing(false);
    } catch (e) {setError(e.message); setBusy(false);}
  }
  async function replay() {
    setError(''); setBusy(true);
    try {
      const response = await request(api+'/replay/'+record.analysis_id, active.token, {method:'POST'});
      const data = await response.json();
      setId(data.analysis_id);
      setRecord({...data, url:record.url});
      setActive({id:data.analysis_id, token:active.token});
      setEditing(false);
    } catch (e) {setError(e.message); setBusy(false);}
  }
  return <><header><div className="brand"><b className="mark" aria-hidden="true">P</b> PhishGuard <b>AI</b></div>
    <span className="headerLabel">Security analysis</span></header>
    <main><div className="heading"><div><div className="kicker">Browser sandbox</div><h1>Interactive Threat Explorer</h1></div>
      {!editing && <button className="secondary" onClick={()=>setEditing(true)}>Open workspace</button>}</div>
    {editing && <section className="setup"><div className="tabs">
      <button aria-pressed={task==='scan'} onClick={()=>setTask('scan')}>New analysis</button>
      <button aria-pressed={task==='open'} onClick={()=>setTask('open')}>Open report</button></div>
      <form onSubmit={submit}><h2>{task==='scan' ? 'Analyze a website' : 'Open an analysis'}</h2>
        <p>{task==='scan' ? 'Inspect a captured page in an isolated browser and trace which elements receive clicks.'
          : 'Enter the analysis ID from a previous scan to inspect its evidence.'}</p>
        {task==='scan' ? <label>Website URL<input type="url" required value={url} maxLength="2048" placeholder="https://example.org" onChange={e=>setUrl(e.target.value)}/></label>
          : <label>Analysis ID<input required pattern="[0-9a-fA-F-]{32,36}" value={id} onChange={e=>setId(e.target.value)}/></label>}
        <div className="fields"><label>Sandbox access token<input required type="password" autoComplete="off" value={token} onChange={e=>{const v=e.target.value; setToken(v); try{localStorage.setItem('phishguard_sandbox_token',v);}catch(_){}}}/></label>
        {task==='scan' && <label>Analysis mode<select value={mode} onChange={e=>setMode(e.target.value)}>
          <option value="analyze">Full analysis</option><option value="interaction-scan">Interaction scan</option>
          <option value="javascript-analysis">JavaScript analysis</option></select></label>}</div>
        <button className="primary" disabled={busy}>{busy?'Analysis in progress…':task==='scan'?'Start analysis':'Load report'} <span aria-hidden="true">↗</span></button>
      </form></section>}
    {error && <p className="error" role="alert">{error}</p>}
    {record && record.status!=='completed' && <section className="status" role="status"><span className="kicker">Analysis status</span>
      <h2>{human(record.status)}</h2><p>{record.url}</p><code>{record.analysis_id}</code>
      {record.error && <p>{record.error}</p>}</section>}
    {record?.report && <Workspace key={record.analysis_id} record={record} token={active.token} replay={replay} busy={busy}/>}
    </main></>;
}

createRoot(document.getElementById('root')).render(<InteractiveThreatExplorer/>);
