"""Mythos-level deep scan script for testing the enhanced Assurix pipeline."""
import asyncio
import warnings

import httpx

warnings.filterwarnings("ignore")


async def mythos_deep_scan():
    target = "https://dj1naq.sytes.net"
    findings = []

    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True, http2=True, verify=False) as client:
        print(f"=== ASSURIX MYTHOS DEEP SCAN: {target} ===\n")

        # Phase 1: Full recon
        try:
            resp = await client.get(target)
            headers = dict(resp.headers)
        except Exception as e:
            print(f"Error fetching target: {e}")
            return

        # Phase 2: Deep surface analysis - crawl additional pages
        pages_to_crawl = [
            "/login", "/admin", "/api", "/robots.txt", "/sitemap.xml",
            "/.env", "/debug", "/swagger.json", "/api/docs", "/graphql",
        ]
        endpoints = []
        auth_pages = []
        forms = []

        for path in pages_to_crawl:
            try:
                r = await client.get(f"{target}{path}", follow_redirects=False)
                if r.status_code == 200:
                    endpoints.append(path)
                    body = r.text[:3000].lower()
                    if "login" in path or "auth" in path or "signin" in path:
                        auth_pages.append({
                            "url": f"{target}{path}",
                            "auth_type": "form_login" if "<form" in r.text.lower() else "unknown",
                        })
                    if "<form" in r.text.lower():
                        forms.append({"action": f"{target}{path}", "method": "GET", "inputs": []})
                    if any(kw in body for kw in ("password", "csrf", "token")):
                        print(f"  [DEEP] Interesting content at {path}: status={r.status_code}")
                elif r.status_code in (301, 302, 303, 307, 308):
                    loc = r.headers.get("location", "")
                    print(f"  [DEEP] Redirect at {path}: {r.status_code} -> {loc[:80]}")
                    endpoints.append(path)
            except Exception:
                continue

        # Phase 3: Security analysis with all enhancements
        from src.agents.webapp import WebappAgent

        agent = WebappAgent()
        surface = {
            "headers": headers,
            "cookies": [],
            "forms": forms,
            "endpoints": endpoints,
            "auth_pages": auth_pages,
            "inputs": [],
            "buttons": [],
            "scripts": [],
            "meta_tags": {},
            "console_errors": [],
            "text_content": "",
            "technologies": [headers.get("server", ""), headers.get("x-powered-by", "")],
            "pages": [],
        }

        # Header analysis
        print("=== SECURITY HEADER ANALYSIS ===")
        hf = agent._analyze_security_headers(headers, target)
        for f in hf:
            print(f'  [{f.get("severity", "info")}] {f["title"]}: {f["description"]}')
        findings.extend(hf)
        if not hf:
            print("  All standard security headers present!")
        print()

        # CSP analysis
        print("=== CSP DEEP ANALYSIS ===")
        csp = headers.get("content-security-policy", "")
        if csp:
            directives = {}
            for part in csp.split(";"):
                part = part.strip()
                if part:
                    tokens = part.split()
                    if tokens:
                        directives[tokens[0]] = tokens[1:]
            print(f"  CSP Directives: {list(directives.keys())}")
            for directive, values in directives.items():
                if "unsafe-inline" in values:
                    print(f"  [!] {directive}: contains unsafe-inline")
                if "unsafe-eval" in values:
                    print(f"  [!] {directive}: contains unsafe-eval")
                if "*" in values:
                    print(f"  [!] {directive}: contains wildcard")
            print()

        cspf = agent._analyze_csp(headers, target)
        for f in cspf:
            print(f'  [{f.get("severity", "info")}] {f["title"]}: {f["description"]}')
        findings.extend(cspf)
        print()

        # Info disclosure
        print("=== INFO DISCLOSURE ===")
        idf = agent._check_info_disclosure(headers, target)
        for f in idf:
            print(f'  [{f.get("severity", "info")}] {f["title"]}: {f["description"]}')
        findings.extend(idf)
        if not idf:
            print("  No info disclosure headers found!")
        print()

        # SSRF surface
        print("=== SSRF SURFACE ANALYSIS ===")
        ssrf = agent._check_ssrf_surface(endpoints, target)
        for f in ssrf:
            print(f'  [{f.get("severity", "info")}] {f["title"]}')
        findings.extend(ssrf)
        if not ssrf:
            print("  No SSRF surface indicators found")
        print()

        # JWT surface
        print("=== JWT/TOKEN SURFACE ANALYSIS ===")
        jwtf = agent._check_jwt_surface(headers, [], target)
        for f in jwtf:
            print(f'  [{f.get("severity", "info")}] {f["title"]}: {f["description"]}')
        findings.extend(jwtf)
        if not jwtf:
            print("  No JWT/token surface indicators found")
        print()

        # Race condition indicators
        print("=== RACE CONDITION INDICATORS ===")
        rcf = agent._check_race_condition_indicators(headers, forms, endpoints, target)
        for f in rcf:
            print(f'  [{f.get("severity", "info")}] {f["title"]}: {f["description"]}')
        findings.extend(rcf)
        if not rcf:
            print("  No race condition indicators found")
        print()

        # Second-order injection
        print("=== SECOND-ORDER INJECTION SURFACE ===")
        soif = agent._check_second_order_injection(forms, endpoints, target)
        for f in soif:
            print(f'  [{f.get("severity", "info")}] {f["title"]}')
        findings.extend(soif)
        if not soif:
            print("  No second-order injection indicators found")
        print()

        # Suspicious points (Mythos-enhanced)
        print("=== SUSPICIOUS POINTS (Mythos-Enhanced) ===")
        from src.agents.browser.suspicious_points import SuspiciousPointDetector

        sp_detector = SuspiciousPointDetector()
        suspicious_points = sp_detector.detect(surface)
        for sp in suspicious_points[:25]:
            print(f"  [{sp.confidence:.2f}] {sp.sp_type}@{sp.location}: {sp.reason}")
            print(f"         vulns: {sp.vuln_types}")
        print(f"  Total: {len(suspicious_points)} suspicious points\n")

        # Missing code detection
        print("=== MISSING CODE DETECTION ===")
        from src.agents.browser.missing_code import MissingCodeDetector

        mcd = MissingCodeDetector()
        mc_findings = mcd._heuristic_detect(surface)
        for f in mc_findings[:15]:
            print(f'  [{f.get("severity", "info")}] {f.get("title", "?")}')
        findings.extend(mc_findings)
        print(f"  Total: {len(mc_findings)} missing control findings\n")

        # Pattern matching (Mythos-enhanced)
        print("=== PATTERN MATCHING (Mythos-Enhanced) ===")
        from src.patterns.library import VulnerabilityPatternLibrary

        pattern_lib = VulnerabilityPatternLibrary()
        for finding in findings:
            matches = pattern_lib.match(finding)
            if matches:
                best_pattern, best_score = matches[0]
                finding["pattern_match"] = {
                    "name": best_pattern.name,
                    "cwe": best_pattern.cwe,
                    "score": round(best_score, 2),
                }
                title = finding.get("title", "?") or ""
                print(f"  {title[:60]:<60} -> {best_pattern.name} ({best_score:.2f})")
        print()

        # Trust scoring
        print("=== TRUST SCORING ===")
        from src.reasoning.trust import TrustScorer

        trust_scorer = TrustScorer()
        scored_findings = trust_scorer.score_findings(findings)
        for f in scored_findings[:10]:
            title = f.get("title", "?") or ""
            trust = f.get("trust_score", 0) or 0
            level = f.get("trust_level", "?") or "?"
            print(f"  [{level}] trust={trust:.2f} | {title[:70]}")
        print()

        # Summary
        print("=" * 60)
        print(f"TOTAL FINDINGS: {len(findings)}")
        by_sev = {}
        for f in findings:
            sev = f.get("severity") or "info"
            by_sev[sev] = by_sev.get(sev, 0) + 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_sev:
                print(f"  {sev}: {by_sev[sev]}")
        print()

        print("=== TOP 5 FINDINGS ===")
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        top = sorted(findings, key=lambda f: severity_order.get(f.get("severity") or "info", 0), reverse=True)[:5]
        for i, f in enumerate(top, 1):
            sev = f.get("severity") or "info"
            title = f.get("title", "?") or "?"
            desc = f.get("description", "") or ""
            print(f"{i}. [{sev.upper()}] {title}")
            print(f"   {desc[:150]}")
            cwe = f.get("cwe_id")
            if cwe:
                print(f"   CWE: {cwe}")
            pm = f.get("pattern_match")
            if pm:
                print(f"   Pattern: {pm['name']} (score: {pm['score']})")
            ts = f.get("trust_score")
            if ts:
                print(f"   Trust: {ts:.2f}")
            print()


if __name__ == "__main__":
    asyncio.run(mythos_deep_scan())