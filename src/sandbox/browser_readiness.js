(() => {
    // Sample only top-document viewport dependencies. Pixel samples also cover painted frames.
    const root = document.documentElement;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT);
    let node = root;
    let inspected = 0;
    let pendingImages = 0;
    let failedImages = 0;
    let busyComponents = 0;
    // This code runs in the inspector's isolated world. A WeakMap keeps decode
    // status without modifying site elements or retaining removed image nodes.
    const decodes = globalThis.__phishGuardImageDecodes ??= new WeakMap();
    while (node && inspected < 1800) {
        inspected++;
        const image = node instanceof HTMLImageElement &&
            Boolean(node.currentSrc || node.src || node.srcset || node.dataset.src || node.dataset.srcset);
        const busy = node.getAttribute("aria-busy") === "true" ||
            (node instanceof HTMLProgressElement && !node.hasAttribute("value"));
        if (image || busy) {
            const box = node.getBoundingClientRect();
            if (box.width > 0 && box.height > 0 && box.right > 0 && box.bottom > 0 &&
                    box.left < innerWidth && box.top < innerHeight &&
                    node.checkVisibility({checkOpacity: true, checkVisibilityCSS: true})) {
                if (busy) busyComponents++;
                if (image) {
                    if (!node.currentSrc || !node.complete) {
                        if (node.complete && (node.src || node.srcset) && !node.naturalWidth) failedImages++;
                        else pendingImages++;
                    } else if (!node.naturalWidth) {
                        failedImages++;
                    } else {
                        let record = decodes.get(node);
                        if (!record || record.src !== node.currentSrc) {
                            record = {src: node.currentSrc, status: "pending"};
                            decodes.set(node, record);
                            node.decode().then(() => record.status = "ready", () => record.status = "failed");
                        }
                        if (record.status === "pending") pendingImages++;
                        if (record.status === "failed") failedImages++;
                    }
                }
            }
        }
        node = walker.nextNode();
    }
    return {
        browser_error_document: location.protocol === "chrome-error:",
        document_complete: document.readyState === "complete",
        pending_images: pendingImages,
        failed_images: failedImages,
        fonts_loading: document.fonts.status === "loading",
        busy_components: busyComponents,
        inspection_limited: Boolean(node),
        scroll_x: scrollX,
        scroll_y: scrollY,
    };
})()
