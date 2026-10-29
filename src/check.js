const MAX_HTML = 262_144;
export function normalizeTarget(value) {
    if (typeof value !== "string" || value.length > 2048)
        throw new Error("Enter an HTTPS URL, up to 2,048 characters.");
    let parsed;
    try {
        parsed = new URL(value.trim());
    }
    catch {
        throw new Error("Enter a complete HTTPS URL, such as https://your-client.com.");
    }
    const host = parsed.hostname.toLowerCase().replace(/\.$/, "");
    if (parsed.protocol !== "https:" || parsed.username || parsed.password || (parsed.port && parsed.port !== "443")) {
        throw new Error("Only HTTPS URLs without credentials or custom ports are supported.");
    }
    if (host.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host)
        || /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|example|onion)$/.test(host)) {
        throw new Error("Use a public website hostname. IP addresses and private networks are not supported.");
    }
    parsed.hostname = host;
    parsed.hash = "";
    return parsed.href;
}
export function isPublicAddress(address) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(address)) {
        const p = address.split(".").map(Number);
        if (p.some(x => x > 255))
            return false;
        const [a, b, c] = p;
        return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
            || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
            || (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99)))
            || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) || (a === 203 && b === 0 && c === 113));
    }
    // URL parsing canonicalizes IPv6, including zero padding, before range checks.
    try {
        const canonical = new URL(`https://[${address}]/`).hostname.slice(1, -1);
        const groups = canonical.split(":");
        const first = parseInt(groups[0] || "0", 16), second = parseInt(groups[1] || "0", 16);
        return first >= 0x2000 && first <= 0x3fff && first !== 0x2002 && first !== 0x3fff
            && !(first === 0x2001 && (second < 0x0200 || second === 0x0db8));
    }
    catch {
        return false;
    }
}
async function verifyPublicHost(host, fetcher, signal) {
    const answers = await Promise.all(["A", "AAAA"].map(async (type) => {
        const response = await fetcher(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
            headers: { Accept: "application/dns-json" }, redirect: "manual", signal,
        });
        if (!response.ok)
            throw new Error("Public DNS could not be verified.");
        const json = await response.json();
        if (json.Status !== 0)
            throw new Error("This hostname did not resolve successfully.");
        return (json.Answer ?? []).filter(a => a.type === 1 || a.type === 28).map(a => a.data);
    }));
    const addresses = answers.flat();
    if (!addresses.length || !addresses.every(isPublicAddress))
        throw new Error("This hostname does not resolve exclusively to public addresses.");
}
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
            await verifyPublicHost(new URL(current).hostname, fetcher, controller.signal);
            // DNS preflight is not connection pinning. Hosted safety also relies on
            // Cloudflare global fetch's public-network boundary with no protected
            // origin/VPC binding. Re-audit egress before porting to a Node server or
            // adding private connectivity. Never use an inbound Request as fetch init.
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
    const fetcher = options.fetcher ?? fetch;
    const timeout = options.timeoutMs ?? 12_000;
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
