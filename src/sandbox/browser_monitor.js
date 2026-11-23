// Reinstalled in each document before application scripts. Values, keystrokes,
// request bodies, and clipboard contents are deliberately never read.
const records = [], installed = new Map(), counts = new Map(), NativeDate = Date;
let documentSequence = 0;
function event(type, el, extra = {}) {
  const count = counts.get(type) || 0;
  if (records.length >= 300 || count >= 48) return;
  counts.set(type, count + 1);
  records.push({type, selector:selector(el), timestamp:new NativeDate().toISOString(), ...extra,
    document_sequence:++documentSequence});
}
Object.defineProperty(window, "__phishguardRead", {value:(command) => {
  if (command === "listeners") return [...installed].filter(([el]) => el.isConnected)
    .map(([el, types]) => [selector(el), types]);
  counts.clear();
  return records.splice(0);
}});
function wrap(obj, key, callback) {
  if (!obj || typeof obj[key] !== "function") return;
  const original = obj[key];
  try {
    obj[key] = function(...args) { return callback.call(this, original, args); };
  } catch (_) { /* Some browser APIs are read-only. */ }
}
function formEvent(form, method, submitter) {
  const override = submitter?.hasAttribute("formaction");
  event("form_submission", form, {method:String(submitter?.formMethod || form.method || "get").toUpperCase(),
    url:String(override ? submitter.formAction : form.action).slice(0,1500),
    credential:!!form.querySelector('input[type="password"]'), blocked:true, mechanism:method});
}
function blockSubmission(e) {
  const form = e.composedPath()[0];
  if (form instanceof HTMLFormElement) formEvent(form, "submit-event", e.submitter);
  e.preventDefault();
}
document.addEventListener("submit", blockSubmission, true);
wrap(HTMLFormElement.prototype, "submit", function() { formEvent(this, "native-submit"); });
document.addEventListener("click", e => event("click", e.composedPath()[0] || e.target, {trusted:e.isTrusted}), true);
wrap(EventTarget.prototype, "addEventListener", function(original, args) {
  const name = args[0];
  if (["click","mousedown","pointerdown","submit"].includes(name)) {
    if (this instanceof Element && (installed.has(this) || installed.size < 350)) {
      const existing = installed.get(this) || [];
      if (!existing.includes(name)) installed.set(this,[...existing,name]);
    }
    event("listener_registration", this, {event:name});
  }
  return Reflect.apply(original,this,args);
});
const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value");
if (descriptor && descriptor.configurable && descriptor.get) {
  Object.defineProperty(HTMLInputElement.prototype,"value",{...descriptor,get() {
    if (this.type === "password") event("credential_access", this);
    return descriptor.get.call(this);
  }});
}
for (const [obj, method, type] of [
  [navigator.clipboard,"read","clipboard_read"],[navigator.clipboard,"readText","clipboard_read"],
  [navigator.clipboard,"write","clipboard_write"],[navigator.clipboard,"writeText","clipboard_write"],
  [navigator.geolocation,"getCurrentPosition","geolocation_request"],
  [navigator.geolocation,"watchPosition","geolocation_request"],
  [navigator.mediaDevices,"getUserMedia","media_permission_request"],
  [window.Notification,"requestPermission","notification_permission_request"],
  [window,"open","popup_attempt"],
]) wrap(obj,method,function(original,args) {
  const extra = {};
  if (type === "popup_attempt" && typeof args[0] === "string") {
    try { extra.url = new URL(args[0],location.href).href.slice(0,1500); } catch (_) {}
  }
  if (method === "getUserMedia") {
    extra.camera = !!args[0]?.video; extra.microphone = !!args[0]?.audio;
  }
  event(type, document.activeElement, extra);
  return Reflect.apply(original,this,args);
});
const observedRoots = new WeakSet();
let observedCount = 0;
function observeOpen(root) {
  if (!root || root.mode !== "open" || observedCount >= 24 || observedRoots.has(root)) return;
  observedCount++; observedRoots.add(root);
  observer.observe(root, options);
  root.addEventListener("submit", e => { if (!e.composed) blockSubmission(e); }, true);
}
const options = {subtree:true,childList:true,attributes:true,attributeOldValue:true,
  attributeFilter:["style","class","hidden","href","src","action","formaction","onclick"]};
const observer = new MutationObserver(changes => {
  const destinations = new Map();
  for (const change of changes.slice(0,64)) {
    if (change.type === "attributes") {
      event("ui_mutation",change.target,{attribute:change.attributeName});
      const attr = change.attributeName, el = change.target;
      if ((attr === "action" && el instanceof HTMLFormElement) ||
          (attr === "formaction" && el.matches("button,input") && el.form)) {
        if (destinations.has(el)) destinations.get(el).count++;
        else destinations.set(el, {prior:change.oldValue, attr, count:1});
      }
      continue;
    }
    for (const node of Array.from(change.addedNodes).slice(0,12)) {
      if (!(node instanceof Element)) continue;
      observeOpen(node.shadowRoot);
      if (node.matches("script")) event("script_inserted",node,{
        url:node.src.slice(0,1500), code:node.src ? "" : (node.textContent || "").slice(0,12000)});
      else if (node.matches("iframe")) event("iframe_inserted",node,{url:node.src.slice(0,1500)});
      else event("element_inserted",node,{tag:node.localName});
    }
  }
  function urlOnly(value) {
    try {
      const dest = new URL(value);
      return /^https?:$/.test(dest.protocol) ? (dest.origin + dest.pathname).slice(0,640) : "";
    } catch (_) { return ""; }
  }
  for (const [el, change] of destinations) {
    const form = el instanceof HTMLFormElement ? el : el.form;
    if (!form || el.getAttribute(change.attr) === change.prior) continue;
    const current = urlOnly(change.attr === "formaction" && el.hasAttribute("formaction") ? el.formAction : form.action);
    // An earlier relative attribute cannot establish the earlier base URL.
    const prior = urlOnly(change.prior);
    if (current && current !== prior) event("form_destination_change",el,{
      form_selector:selector(form),attribute:change.attr,from_url:prior,url:current,
      coalesced:change.count>1,batch_truncated:changes.length>64});
  }
});
observer.observe(document, options);
wrap(Element.prototype, "attachShadow", function(original,args) {
  const root = Reflect.apply(original,this,args);
  observeOpen(root);
  return root;
});
