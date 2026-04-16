/**
 * ScamShield Echo — background.js
 * UNIVERSAL FILE: Logic + UI + Injection
 * Architecture: Scan-First Interception
 */

if (typeof window === 'undefined') {
    // ─────────────────────────────────────────────
    // BACKGROUND SERVICE WORKER MODE
    // ─────────────────────────────────────────────

    const VT_API_KEY = "7c10d0d4f3fdb50127febc9b3be778cd187085f0e9fb8c6de6d7795cf712ed6e";
    const WHOIS_API_KEY = "at_bPGxtJFDZaaIUokezqwzBwI282wEm";
    const UI_PAGE = chrome.runtime.getURL("ui.html");
    const IGNORED = ["chrome:", "about:", "data:", "file:", "chrome-extension:"];
    const TOP_BRANDS = ["facebook", "meta", "google", "amazon", "netflix", "paypal", "microsoft", "apple", "linkedin", "instagram", "whatsapp", "bankofamerica", "hsbc", "icici", "sbi"];

    const ML = {
        w: { l: 0.005, i: 2.5, d: 0.5, h: 1, n: 1.2, s: 2, b: -3 },
        s(z) { return 1 / (1 + Math.exp(-z)); },
        p(url) {
            try {
                const t = url.split("?")[0], n = new URL(t).hostname, r = { l: t.length, i: /^(\d{1,3}\.){3}\d{1,3}$/.test(n) ? 1 : 0, d: (n.match(/\./g) || []).length, h: n.includes("-") ? 1 : 0, n: /\d/.test(n) ? 1 : 0, s: /(login|verify|bank|secure|update|kyc)/.test(t) ? 1 : 0 };
                let a = this.w.b + this.w.l * r.l + this.w.i * r.i + this.w.d * r.d + this.w.h * r.h + this.w.n * r.n + this.w.s * r.s;
                const i = this.s(a); return { p: i, s: i > 0.6 };
            } catch { return { p: 0, s: false }; }
        }
    };

    function isHomograph(hostname) {
        if (hostname.startsWith('xn--')) return true;
        const lookalikes = /[аеіоурху]/;
        return lookalikes.test(hostname);
    }

    async function getAge(e) {
        try {
            const t = new URL(e).hostname;
            const n = await fetch(`https://www.whoisxmlapi.com/whoisapi/v1?apiKey=${WHOIS_API_KEY}&domainName=${t}&outputFormat=JSON`);
            const r = await n.json();
            const a = r.WhoisRecord?.createdDate || r.WhoisRecord?.registryData?.createdDate;
            return a ? Math.ceil((new Date() - new Date(a)) / 864e5) : 999;
        } catch { return 999; }
    }

    async function checkVT(e) {
        try {
            const t = await fetch("https://www.virustotal.com/api/v3/urls", { method: "POST", headers: { "x-apikey": VT_API_KEY }, body: new URLSearchParams({ url: e }) });
            const n = await t.json(), r = n.data?.id;
            if (!r) return { s: false };
            await new Promise((e => setTimeout(e, 2000)));
            const a = await fetch(`https://www.virustotal.com/api/v3/analyses/${r}`, { headers: { "x-apikey": VT_API_KEY } });
            const s = await a.json(), i = s.data?.attributes?.stats || {};
            return { s: i.malicious >= 2 || i.suspicious >= 5, r: i.malicious ? `Flagged by ${i.malicious} engines` : "Clean" };
        } catch { return { s: false }; }
    }

    // Shared global 'check' export (re-used by UI)
    self.universalCheck = async function(url, pageContext = {}) {
        const domain = new URL(url).hostname;
        const whitelist = await chrome.storage.local.get("whitelist");
        if (whitelist.whitelist && whitelist.whitelist.includes(domain)) return { isScam: false };

        const cacheKey = `s_${url}`;
        const cached = await chrome.storage.local.get(cacheKey);
        if (!pageContext.force && cached[cacheKey] && !cached[cacheKey].isContextual) return cached[cacheKey];
        
        const [age, vt] = await Promise.all([getAge(url), checkVT(url)]);
        const ml = ML.p(url);
        
        // Community Block Check (Render)
        let communityBlocked = false;
        try {
            const checkRes = await fetch(`https://tecknotsava.onrender.com/api/check?url=${encodeURIComponent(url)}`);
            const checkData = await checkRes.json();
            if (checkData.blocked) {
                communityBlocked = true;
            }
        } catch (e) { console.log("Community check failed, falling back to heuristics"); }

        let isScam = false, reason = "", source = "General Heuristics";
        if (communityBlocked) { isScam = true; reason = "Blocked by community (multiple users reported this site)"; source = "Community Shield"; }
        else if (vt.s) { isScam = true; reason = vt.r; source = "VirusTotal"; }
        else if (age < 14) { isScam = true; reason = `New domain (${age} days old)`; source = "Reputation"; }
        else if (ml.s) { isScam = true; reason = "AI model flagged pattern"; source = "AI Model"; }
        else if (isHomograph(domain)) { isScam = true; reason = "Homograph spoofing detected"; source = "URL Spoofing"; }
        if (pageContext.insecureForm) { isScam = true; reason = "Insecure sensitive form (HTTP)"; source = "Data Privacy"; }
        else if (pageContext.formLeak) { isScam = true; reason = "Form data leak detected"; source = "Data Privacy"; }
        else if (pageContext.obfuscated) { isScam = true; reason = "High concentration of obfuscated scripts"; source = "Code Analysis"; }
        const brand = (pageContext.title || "").toLowerCase();
        for (const b of TOP_BRANDS) {
            if (brand.includes(b) && !domain.toLowerCase().includes(b)) {
                isScam = true; reason = `Brand Impersonation: Claims ${b}`; source = "Identity Protection"; break;
            }
        }
        const result = { isScam, reason, source, mlScore: ml.p };
        
        // Report to Dashboard (Render)
        fetch("https://tecknotsava.onrender.com/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, reason: result.isScam ? reason : "Safe", source: result.isScam ? source : "Heuristics" })
        }).catch(err => console.log("Dashboard report suppressed or failed"));

        if (!pageContext.title) chrome.storage.local.set({ [cacheKey]: result });
        return result;
    };

    // ─────────────────────────────────────────────
    // SCAN-FIRST INTERCEPTION
    // ─────────────────────────────────────────────
    chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
        if (d.frameId !== 0 || IGNORED.some(p => d.url.startsWith(p)) || d.url.startsWith(UI_PAGE)) return;

        const domain = new URL(d.url).hostname;
        const cacheRaw = await chrome.storage.local.get([`s_${d.url}`, "whitelist"]);
        const isSafe = cacheRaw.whitelist?.includes(domain) || (cacheRaw[`s_${d.url}`] && !cacheRaw[`s_${d.url}`].isScam);

        if (!isSafe) {
            // IMMEDIATE STOP & SCAN
            const target = encodeURIComponent(d.url);
            chrome.tabs.update(d.tabId, { url: `${UI_PAGE}?mode=scanning&url=${target}` });
        }
    });

    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (msg.type === "CHECK_PAGE_CONTEXT" && sender.tab) {
            self.universalCheck(sender.tab.url, msg.data).then(r => {
                if (r.isScam) {
                    const params = new URLSearchParams({ mode: "blocked", url: sender.tab.url, reason: r.reason, mlScore: r.mlScore, source: r.source });
                    chrome.tabs.update(sender.tab.id, { url: `${UI_PAGE}?${params.toString()}` });
                }
            });
        }
        if (msg.type === "WHITELIST_DOMAIN" && msg.url) {
            const domain = new URL(msg.url).hostname;
            chrome.storage.local.get("whitelist", (data) => {
                const list = data.whitelist || [];
                if (!list.includes(domain)) list.push(domain);
                chrome.storage.local.set({ "whitelist": list }, () => sendResponse({ ok: true }));
            });
            return true;
        }
    });

} else {
    // ─────────────────────────────────────────────
    // UI MODE (UNIVERSAL LOGIC)
    // ─────────────────────────────────────────────
    const params = new URLSearchParams(window.location.search);
    const mode = params.get('mode');

    // Reuse the universalCheck function for UI-based scanning
    async function runUIScan(url) {
        // Find the background's check logic (abstracted here for single-file UI access)
        // Since background.js is loaded in Window, we must re-implement or call bg via messaging.
        // Easiest for single-file: Re-implement small wrapper.
        chrome.runtime.getBackgroundPage = null; // MV3 doesn't have this.
        
        // We Use Messaging to get the background to run the Heavy Scan
        return new Promise(resolve => {
            // Need a way for UI to trigger background scan
            chrome.runtime.sendMessage({type: 'DO_HEAVY_SCAN', url}, resolve);
        });
    }

    if (mode === 'scanning') {
        document.body.classList.add('full');
        document.getElementById('mode-popup').classList.add('hidden');
        document.getElementById('mode-scanning').classList.remove('hidden');
        const target = decodeURIComponent(params.get('url'));
        document.getElementById('s-url').textContent = target;

        // Perform Scan
        chrome.runtime.sendMessage({type: 'DO_HEAVY_SCAN', url: target}, (res) => {
            if (res.isScam) {
                window.location.href = `${window.location.protocol}//${window.location.host}${window.location.pathname}?mode=blocked&url=${encodeURIComponent(target)}&reason=${encodeURIComponent(res.reason)}&mlScore=${res.mlScore}&source=${encodeURIComponent(res.source)}`;
            } else {
                // Success! Whitelist and Go
                chrome.runtime.sendMessage({type: 'WHITELIST_DOMAIN', url: target}, () => {
                    window.location.href = target;
                });
            }
        });
    } else if (mode === 'blocked') {
        document.body.classList.add('full');
        document.getElementById('mode-popup').classList.add('hidden');
        document.getElementById('mode-blocked').classList.remove('hidden');
        const blockedUrl = decodeURIComponent(params.get('url'));
        document.getElementById('b-url').textContent = blockedUrl;
        document.getElementById('b-reason').textContent = decodeURIComponent(params.get('reason'));
        document.getElementById('b-score').textContent = (parseFloat(params.get('mlScore')) * 100).toFixed(1) + '%';
        document.getElementById('b-source').textContent = params.get('source');

        document.getElementById('b-back').onclick = () => { history.length > 1 ? history.back() : window.location.href='about:newtab'; };
        document.getElementById('b-proceed').onclick = () => {
            if (confirm('Proceed anyway?')) {
                chrome.runtime.sendMessage({type:'WHITELIST_DOMAIN', url: blockedUrl}, () => {
                    window.location.href = blockedUrl;
                });
            }
        };
    } else {
        chrome.tabs.query({active:true, currentWindow:true}, ([tab]) => {
            if(tab && tab.url) {
                try { document.getElementById('p-domain').textContent = new URL(tab.url).hostname; } catch { document.getElementById('p-domain').textContent = "Browser"; }
            }
            document.getElementById('p-refresh').onclick = () => { chrome.tabs.reload(tab.id); window.close(); };
        });
    }
}

// Global Message Switch for DO_HEAVY_SCAN
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
    chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
        if (msg.type === 'DO_HEAVY_SCAN') {
            // Need to handle this only in Background script
            if (typeof window === 'undefined') {
                self.universalCheck(msg.url).then(sendResponse);
                return true; 
            }
        }
    });
}
