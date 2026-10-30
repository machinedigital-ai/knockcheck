import { normalizeTarget } from './policy.js';
import { safeFetch } from './network.js';
export { normalizeTarget, isPublicAddress } from './policy.js';
const MAX_HTML = 262_144;
async function readPage(input, fetcher, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        let current = normalizeTarget(input);
        const visited = new Set();
        for (let i = 0; i < 5; i++) {
            if (visited.has(current))
                throw new Error("The website has a redirect loop.");
            visited.add(current);
            const response = await fetcher(current, {
                method: "GET", redirect: "manual", signal: controller.signal,
                headers: { "User-Agent": "KnockCheck/1.0 (website-health-check)", Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1" },
                credentials: "omit",
            });
            if ([301, 302, 303, 307, 308].includes(response.status)) {
                await response.body?.cancel();
                const location = response.headers.get("location");
                if (!location)
                    throw new Error("A redirect has no destination.");
                current = normalizeTarget(new URL(location, current).href);
                continue;
            }
            const isHtml = /(?:text\/html|application\/xhtml\+xml)/i.test(response.headers.get("content-type") ?? "");
            const encoding = response.headers.get("content-encoding");
            if (encoding && encoding.toLowerCase() !== "identity") {
                await response.body?.cancel();
                throw new Error("The server returned unsupported compressed content.");
            }
            let html = "", truncated = false;
            if (response.body && isHtml && response.ok) {
                const reader = response.body.getReader();
                const decoder = new TextDecoder();
                let length = 0;
                try {
                    while (true) {
                        const part = await reader.read();
                        if (part.done)
                            break;
                        const remaining = MAX_HTML - length;
                        html += decoder.decode(part.value.subarray(0, remaining), { stream: true });
                        length += part.value.length;
                        if (length > MAX_HTML) {
                            truncated = true;
                            await reader.cancel();
                            break;
                        }
                    }
                    html += decoder.decode();
                }
                finally {
                    reader.releaseLock();
                }
            }
            else
                await response.body?.cancel();
            return { url: current, status: response.status, html, truncated, isHtml };
        }
        throw new Error("The website redirected too many times.");
    }
    catch (error) {
        // Node may surface a cancelled response body as ECONNRESET rather
        // than AbortError. Preserve the check's deadline semantics.
        if (controller.signal.aborted) throw new DOMException('The check timed out.', 'AbortError');
        throw error;
    }
    finally {
        clearTimeout(timer);
    }
}
function statusResult(label, page) {
    const blocked = [401, 403, 429].includes(page.status);
    const pass = page.status >= 200 && page.status < 300;
    return {
        label, status: pass ? "pass" : blocked ? "unknown" : "fail", url: page.url, httpStatus: page.status,
        detail: pass ? `Responded with HTTP ${page.status}.` : blocked ? `HTTP ${page.status}: access or rate limiting prevents a reliable check.` : `Responded with HTTP ${page.status}; review this destination.`,
    };
}
function normalizedLink(url) {
    const value = new URL(url);
    value.hash = "";
    value.pathname = value.pathname.replace(/\/$/, "") || "/";
    return value.href;
}
function hrefAttribute(tag) {
    // Consume full attribute values so data-href or text inside another value
    // cannot be mistaken for an actual href attribute.
    const attributes = tag.replace(/^<\w+\b/i, "").replace(/>$/, "");
    const pattern = /([^\s=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;
    let match;
    while ((match = pattern.exec(attributes))) {
        if (match[1].toLowerCase() === "href")
            return match[2] ?? match[3] ?? match[4] ?? "";
    }
    return null;
}
export function hasEnquiryLink(html, pageUrl, targets) {
    // Static anchors only; strip script/style/comments to avoid counting code as a link.
    const clean = html.replace(/<!--[\s\S]*?-->|<script\b[\s\S]*?<\/script\s*>|<style\b[\s\S]*?<\/style\s*>/gi, "");
    let base = pageUrl;
    const baseTag = clean.match(/<base\b[^>]*>/i);
    const baseHref = baseTag ? hrefAttribute(baseTag[0]) : null;
    if (baseHref) {
        try {
            base = new URL(baseHref, pageUrl).href;
        }
        catch { /* use page */ }
    }
    const expected = targets.map(normalizedLink);
    const anchors = clean.match(/<a\b[^>]*>/gi) ?? [];
    return anchors.some(tag => {
        const attribute = hrefAttribute(tag);
        if (attribute === null)
            return false;
        const href = attribute.replace(/&(?:amp|#38|#x26);/gi, "&");
        try {
            return expected.includes(normalizedLink(new URL(href, base).href));
        }
        catch {
            return false;
        }
    });
}
export async function checkWebsite(url, contactUrl, options = {}) {
    const fetcher = options.fetcher ?? safeFetch;
    const timeout = options.timeoutMs ?? 12_000;
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > 60000) throw new Error("Timeout must be between 1 and 60,000 milliseconds.");
    const pages = await Promise.allSettled([readPage(url, fetcher, timeout), readPage(contactUrl, fetcher, timeout)]);
    const results = pages.map((item, i) => item.status === "fulfilled"
        ? statusResult(i === 0 ? "Website availability" : "Enquiry destination", item.value)
        : { label: i === 0 ? "Website availability" : "Enquiry destination", status: "unknown", detail: item.reason?.name === "AbortError" ? "The check timed out. Retry or inspect the website manually." : String(item.reason?.message ?? "The request could not be completed.").slice(0, 220) });
    const homepage = pages[0].status === "fulfilled" ? pages[0].value : null;
    const contact = pages[1].status === "fulfilled" ? pages[1].value : null;
    if (homepage?.isHtml && homepage.status >= 200 && homepage.status < 300) {
        const found = hasEnquiryLink(homepage.html, homepage.url, [contactUrl, ...(contact ? [contact.url] : [])]);
        results.push({ label: "Enquiry link on homepage", status: found ? "pass" : "unknown", detail: found ? "A static link to the configured enquiry destination was found." : homepage.truncated ? "Not found in the inspected HTML portion. The page exceeded the size limit." : "Not found in the static HTML. It may be rendered by JavaScript or behind a menu; inspect it manually." });
    }
    else
        results.push({ label: "Enquiry link on homepage", status: "unknown", detail: "The homepage HTML was unavailable for inspection." });
    const failed = results.some(r => r.status === "fail");
    const unknown = results.some(r => r.status === "unknown");
    return { status: failed ? "attention" : unknown ? "unknown" : "healthy", summary: failed ? "An HTTP failure needs a closer look." : unknown ? "Some checks need manual confirmation." : "Both pages responded and the enquiry link was found.", results };
}
