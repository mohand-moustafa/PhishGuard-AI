// Executed within a browser frame. Points are in frame-local CSS pixels.
const control = 'a[href],button,input,textarea,select,label,form,iframe,summary,[role="button"],[role="link"],[onclick],[tabindex],[contenteditable="true"]';
const cssCache = new WeakMap();
function style(el) {
  if (!cssCache.has(el)) cssCache.set(el, getComputedStyle(el));
  return cssCache.get(el);
}
function opacityOf(el) {
  let opacity = 1;
  for (let n = el; n; n = composedParent(n)) opacity *= Number(style(n).opacity);
  return opacity;
}
function suppressedByAncestor(el) {
  for (let n = composedParent(el); n; n = composedParent(n)) {
    if (style(n).display === "none" || style(n).contentVisibility === "hidden") return true;
  }
  return false;
}
function related(a, b) {
  function contains(a,b) { for (let n=b; n; n=composedParent(n)) if (n===a) return true; return false; }
  return contains(a,b) || contains(b,a) || a.control === b || b.control === a ||
    (a.closest("label")?.control === b) || (b.closest("label")?.control === a);
}
function emptyLayer(el, css) {
  return !el.shadowRoot && !el.localName.includes("-") && !el.hasAttribute("is") &&
    !el.firstElementChild && !(el.textContent || "").trim() &&
    !el.matches("iframe,input,button,select,textarea,img,canvas,video") &&
    css.backgroundImage === "none" && css.backgroundColor === "rgba(0, 0, 0, 0)" &&
    ["Top","Right","Bottom","Left"].every(side => parseFloat(css["border"+side+"Width"]) === 0) &&
    css.boxShadow === "none" && ["::before","::after"].every(p => {
      const content = getComputedStyle(el, p).content;
      return content === "none" || content === "normal";
    });
}
const regions = [], scripts = [], shadowHosts = [];
let nodes = 0, candidates = 0, sampleCount = 0, shadowRoots = 0, shadowTruncated = false;
const walks = [document.createTreeWalker(document.documentElement, NodeFilter.SHOW_ELEMENT)];
while (nodes < limits.nodes && walks.length) {
  const walker = walks[walks.length-1];
  if (!walker.nextNode()) { walks.pop(); continue; }
  nodes++;
  const el = walker.currentNode;
  if (el.shadowRoot) {
    if (shadowRoots < limits.shadows && walks.length <= 4) {
      walks.push(document.createTreeWalker(el.shadowRoot,NodeFilter.SHOW_ELEMENT));
      shadowHosts.push(selector(el));
      shadowRoots++;
    } else shadowTruncated = true;
  }
  const tag = el.localName;
  const handlers = el.getAttributeNames().filter(n => /^on[a-z]+$/.test(n)).slice(0, 8);
  const sel = selector(el);
  if (scripts.length < 80 && tag === "script") {
    scripts.push({kind: el.src ? "external" : "inline", source: el.src || location.href,
      code: el.src ? "" : (el.textContent || "").slice(0, 24000), selector: sel});
  }
  for (const name of handlers) {
    if (scripts.length < 80) scripts.push({kind: "handler", source: location.href,
      code: (el.getAttribute(name) || "").slice(0, 3000), selector: sel, event: name});
  }
  const css = style(el);
  const positioned = ["fixed", "absolute", "sticky"].includes(css.position);
  const rect = el.getBoundingClientRect();
  const listener = listeners.has(sel);
  const interactive = el.matches(control) || handlers.length > 0 || listener || css.cursor === "pointer";
  if (!interactive && !(positioned && rect.width > 0 && rect.height > 0)) continue;
  candidates++;
  if (regions.length >= limits.regions) continue;
  const effective = opacityOf(el), empty = positioned && emptyLayer(el, css);
  const hidden = effective <= 0.10 || css.visibility !== "visible" || css.display === "none" || empty ||
    suppressedByAncestor(el);
  const left = Math.max(0, rect.left), right = Math.min(innerWidth, rect.right);
  const top = Math.max(0, rect.top), bottom = Math.min(innerHeight, rect.bottom);
  const offscreen = !(right > left && bottom > top);
  const points = [];
  function sample(fx, fy) {
    if (sampleCount >= limits.points || offscreen) return;
    const x = Math.floor(left + (right-left-1)*fx), y = Math.floor(top + (bottom-top-1)*fy);
    if (points.some(p => p.x === x && p.y === y)) return;
    sampleCount++;
    const {hit,stack} = hitStack(x,y);
    if (!hit) return;
    const first = hit === el || el.contains(hit);
    let owner = hit;
    while (owner && !owner.matches(control) && !["absolute","fixed","sticky"].includes(style(owner).position) &&
           !listeners.has(selector(owner))) owner = composedParent(owner);
    const beneath = stack.find(n => n !== hit && n.matches(control) &&
      !n.matches("form,iframe") && !related(n, hit) && style(n).visibility === "visible" &&
      opacityOf(n) > 0.25);
    points.push({x,y,hit:selector(hit),receiver:selector(hit),owner:selector(owner || hit),stack:stack.slice(0,6).map(selector),
      receives:first, expected: beneath ? selector(beneath) : "",
      covered:!first && stack.includes(el) && !related(el, hit)});
  }
  sample(0.5,0.5);
  if (hidden || positioned || el.matches("form,iframe") || points.some(p => p.covered || p.expected)) {
    for (const fx of [0.04,0.5,0.96]) for (const fy of [0.04,0.5,0.96]) sample(fx,fy);
  } else {
    sample(0.10,0.15); sample(0.90,0.85);
  }
  const formEl = el.closest("form") || el.form;
  const a11y = /(?:^|\s)(?:sr-only|visually-hidden|screen-reader-text)(?:\s|$)/i.test(el.className) ||
    (tag === "input" && el.labels?.length > 0 && ["checkbox","radio","file"].includes(el.type));
  const text = (el.getAttribute("aria-label") || el.innerText || el.title ||
    (el.matches('input[type="button"],input[type="submit"]') ? el.value : "") || "").slice(0,160);
  const visibleText = hidden || offscreen ? "" : (el.innerText || "").trim().slice(0,160);
  const inputType = typeof el.type === "string" ? el.type : "";
  const roleAttr = (typeof el.getAttribute === "function" && el.getAttribute("role")) || "";
  regions.push({selector:sel,local_selector:localSelector(el),shadow_path:shadowPath(el),tag,text,
    visible_text:visibleText,role:roleAttr, input_type:inputType,
    attributes:{name:(el.getAttribute("name") || "").slice(0,96), type:(el.getAttribute("type") || "").slice(0,40),
      autocomplete:(el.getAttribute("autocomplete") || "").slice(0,80), role:roleAttr.slice(0,80)},
    bbox:{x:rect.x,y:rect.y,width:rect.width,height:rect.height},
    css:{opacity:css.opacity,visibility:css.visibility,display:css.display,
      pointerEvents:css.pointerEvents,zIndex:css.zIndex,position:css.position,transform:css.transform,
      clipPath:css.clipPath,cursor:css.cursor,backgroundColor:css.backgroundColor},
    effective_opacity:effective,empty_layer:empty,interactive,hidden,offscreen,
    covers_viewport:!offscreen && (right-left)*(bottom-top) >= innerWidth*innerHeight*.90,
    accessibility:!!a11y,disabled:!!el.disabled,points,
    handlers:[...new Set([...handlers,...(listeners.get(sel) || [])])],
    destination: String(el.getAttribute("formaction") ? el.formAction :
      (el.href || (tag === "iframe" ? el.src : "") || formEl?.action || "")).slice(0,1500),
    form:formEl ? selector(formEl) : "",
    credential:el.matches('input[type="password"]') || !!formEl?.querySelector('input[type="password"]')});
}
return {regions,scripts,nodes,candidates,sampleCount,shadowRoots,shadowHosts,shadowTruncated,node_limit:nodes === limits.nodes,
  viewport:{width:innerWidth,height:innerHeight}};
