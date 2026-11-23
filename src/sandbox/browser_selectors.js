// Shared by the read-only inspector and the in-page event recorder.
function localSelector(el) {
  if (!(el instanceof Element)) return "";
  const parts = [];
  for (let n = el; n && parts.length < 16; n = n.parentElement) {
    if (n.id && n.id.length <= 96 && n.getRootNode().getElementById?.(n.id) === n) {
      parts.unshift("#" + CSS.escape(n.id));
      break;
    }
    let i = 1;
    for (let s = n.previousElementSibling; s; s = s.previousElementSibling) {
      if (s.localName === n.localName) i++;
    }
    parts.unshift(CSS.escape(n.localName) + ":nth-of-type(" + i + ")");
  }
  return parts.join(" > ").slice(0, 800);
}
function shadowPath(el) {
  const path = [];
  let root = el?.getRootNode?.();
  while (root instanceof ShadowRoot && root.mode === "open" && path.length < 4) {
    path.unshift(localSelector(root.host));
    root = root.host.getRootNode();
  }
  return root instanceof ShadowRoot ? null : path;
}
function selector(el) {
  const path = shadowPath(el);
  return path ? [...path, localSelector(el)].join(" >>> ").slice(0, 800) : "";
}
function composedParent(el) {
  return el.assignedSlot || el.parentElement || el.getRootNode()?.host || null;
}
function hitStack(x,y) {
  let root = document, first = null, stack = [];
  for (let level = 0; level <= 4; level++) {
    const hit = root.elementFromPoint(x,y);
    if (!hit || hit === first) break;
    first = hit;
    stack = [...new Set([...root.elementsFromPoint(x,y).slice(0,16),...stack])].slice(0,24);
    if (!hit.shadowRoot) break;
    root = hit.shadowRoot;
  }
  return {hit:first, stack};
}
