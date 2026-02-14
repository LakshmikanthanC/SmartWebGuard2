"""
AI-Powered Website Safety Analyzer v3
- Categorized threat detection with detailed explanations
- Severity-scored individual findings
- Structured report data for export
"""

import re
import ssl
import socket
import hashlib
import urllib.parse
import time
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class ThreatFinding:
    """Structured threat finding with category, severity, and explanation."""

    def __init__(self, category, name, severity, description, evidence="",
                 recommendation="", risk_points=0):
        self.category = category
        self.name = name
        self.severity = severity  # critical, high, medium, low, info
        self.description = description
        self.evidence = evidence
        self.recommendation = recommendation
        self.risk_points = risk_points

    def to_dict(self):
        return {
            "category": self.category,
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "risk_points": self.risk_points,
        }


# Threat categories
CAT_MALWARE = "Malware"
CAT_PHISHING = "Phishing"
CAT_SSL = "SSL/TLS"
CAT_NETWORK = "Network"
CAT_CONTENT = "Content"
CAT_STRUCTURE = "URL Structure"
CAT_REPUTATION = "Reputation"
CAT_SCRIPT = "Malicious Script"
CAT_CRYPTO = "Cryptominer"
CAT_PRIVACY = "Privacy"
CAT_REDIRECT = "Redirect"
CAT_HEADERS = "Security Headers"


class URLAnalyzer:

    def __init__(self):
        self.suspicious_tlds = [
            ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
            ".club", ".work", ".date", ".racing", ".win", ".bid",
            ".stream", ".download", ".loan", ".men", ".click",
            ".link", ".party", ".review", ".science", ".zip", ".mov"
        ]

        self.trusted_domains = [
            "google.com", "youtube.com", "facebook.com", "amazon.com",
            "wikipedia.org", "twitter.com", "instagram.com", "linkedin.com",
            "microsoft.com", "apple.com", "github.com", "stackoverflow.com",
            "reddit.com", "netflix.com", "whatsapp.com", "zoom.us",
            "dropbox.com", "salesforce.com", "adobe.com", "shopify.com",
            "wordpress.com", "medium.com", "cloudflare.com", "npmjs.com",
            "pypi.org", "docker.com", "elastic.co", "mongodb.com",
            "yahoo.com", "bing.com", "twitch.tv", "spotify.com",
            "paypal.com", "stripe.com", "slack.com", "notion.so",
            "figma.com", "vercel.com", "netlify.com", "heroku.com",
        ]

        self.phishing_keywords = [
            "login", "signin", "sign-in", "verify", "verification",
            "account", "update", "secure", "banking", "confirm",
            "password", "credential", "authenticate", "wallet",
            "suspended", "unusual", "activity", "limited", "restore",
            "unlock", "security", "alert", "notification", "urgent",
            "expire", "compromised", "unauthorized", "validate",
        ]

        self.brand_names = [
            "paypal", "amazon", "apple", "microsoft", "google",
            "facebook", "netflix", "instagram", "whatsapp", "twitter",
            "linkedin", "dropbox", "adobe", "chase", "wellsfargo",
            "bankofamerica", "citibank", "hsbc", "barclays",
        ]

        self.suspicious_patterns = [
            (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', "IP address in URL"),
            (r'[a-zA-Z0-9]{30,}', "Very long random string"),
            (r'@', "@ symbol (URL obfuscation)"),
            (r'\.exe|\.scr|\.bat|\.cmd|\.ps1', "Executable file extension"),
            (r'\.zip|\.rar|\.7z', "Archive file extension"),
            (r'data:', "Data URI scheme"),
            (r'javascript:', "JavaScript URI scheme"),
            (r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}',
             "Heavy percent encoding"),
            (r'-{3,}', "Multiple consecutive hyphens"),
            (r'\.(php|asp|jsp)\?.*=.*&.*=', "Complex server-side query"),
        ]

        self.malware_file_patterns = [
            (r'\.exe(\?|$|&)', "Windows executable (.exe)"),
            (r'\.msi(\?|$|&)', "Windows installer (.msi)"),
            (r'\.dll(\?|$|&)', "Dynamic library (.dll)"),
            (r'\.scr(\?|$|&)', "Screensaver file (.scr) — often malware"),
            (r'\.bat(\?|$|&)', "Batch file (.bat)"),
            (r'\.cmd(\?|$|&)', "Command file (.cmd)"),
            (r'\.ps1(\?|$|&)', "PowerShell script (.ps1)"),
            (r'\.vbs(\?|$|&)', "VBScript file (.vbs)"),
            (r'\.wsf(\?|$|&)', "Windows script (.wsf)"),
            (r'\.apk(\?|$|&)', "Android package (.apk)"),
            (r'\.dmg(\?|$|&)', "macOS disk image (.dmg)"),
            (r'\.iso(\?|$|&)', "Disk image (.iso)"),
            (r'download.*free', "Free download pattern"),
            (r'free.*download', "Free download pattern"),
            (r'crack.*software', "Software crack"),
            (r'keygen', "Key generator"),
            (r'warez', "Pirated software"),
            (r'torrent', "Torrent reference"),
        ]

        self.malicious_js_patterns = [
            (r'eval\s*\(\s*unescape', "eval(unescape()) — code execution via decoding"),
            (r'eval\s*\(\s*atob', "eval(atob()) — base64 decoded execution"),
            (r'eval\s*\(\s*String\.fromCharCode',
             "eval(String.fromCharCode()) — char code execution"),
            (r'document\.write\s*\(\s*unescape',
             "document.write(unescape()) — DOM injection"),
            (r'document\.cookie', "document.cookie access — cookie stealing"),
            (r'\.createElement\s*\(\s*["\'](?:iframe|script)',
             "Dynamic iframe/script creation"),
            (r'XMLHttpRequest.*(?:password|credential|token|session)',
             "XHR with sensitive data keywords"),
            (r'new\s+ActiveXObject', "ActiveXObject — IE exploitation"),
            (r'WScript\.Shell', "WScript.Shell — system command execution"),
            (r'\.execScript', "execScript — legacy script execution"),
            (r'fromCharCode.*fromCharCode.*fromCharCode',
             "Chained fromCharCode — obfuscated payload"),
            (r'(?:\\x[0-9a-fA-F]{2}){10,}',
             "Hex-encoded string — hidden payload"),
            (r'(?:\\u[0-9a-fA-F]{4}){10,}',
             "Unicode-encoded string — hidden payload"),
        ]

        self.cryptominer_patterns = [
            (r'coinhive', "CoinHive miner"),
            (r'cryptonight', "CryptoNight algorithm"),
            (r'coin-?hive', "CoinHive variant"),
            (r'jsecoin', "JSEcoin miner"),
            (r'cryptoloot', "CryptoLoot miner"),
            (r'minero\.cc', "Minero miner"),
            (r'webminepool', "WebMinePool"),
            (r'coinimp', "CoinIMP miner"),
            (r'crypto-?loot', "CryptoLoot variant"),
            (r'authedmine', "AuthedMine"),
            (r'CryptoNight', "CryptoNight implementation"),
            (r'stratum\+tcp', "Mining pool stratum protocol"),
        ]

        self.session = None
        if HAS_REQUESTS:
            self.session = requests.Session()
            self.session.headers.update({
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            })
            self.session.max_redirects = 10
            self.session.verify = True

    def analyze(self, url, deep_scan=True):
        start_time = time.time()

        result = {
            "url": url,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_type": "deep" if deep_scan else "quick",
            "safe": True,
            "risk_score": 0,
            "risk_level": "safe",

            # Detailed findings (new structured format)
            "findings": [],
            "finding_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "categories_detected": [],

            # Legacy compatibility
            "threats": [],
            "warnings": [],
            "info": [],
            "recommendations": [],
            "malware_indicators": [],
            "phishing_indicators": [],

            "analysis": {
                "domain": {},
                "url_structure": {},
                "ssl": {},
                "content": {},
                "reputation": {},
                "redirects": {},
                "headers": {},
                "scripts": {},
                "forms": {},
                "iframes": {},
                "metadata": {},
            },

            "report": {
                "generated_at": datetime.utcnow().isoformat(),
                "scanner_version": "3.0",
                "scan_type": "deep" if deep_scan else "quick",
            },
            "scan_duration_ms": 0,
        }

        try:
            parsed = self._parse_url(url)
            if not parsed:
                self._add_finding(result, ThreatFinding(
                    CAT_STRUCTURE, "Invalid URL", "critical",
                    "The provided URL is malformed or invalid and cannot be parsed.",
                    evidence=url,
                    recommendation="Verify the URL is correctly formatted.",
                    risk_points=95,
                ))
                self._finalize(result, start_time)
                return result

            result["analysis"]["url_structure"] = parsed

            # Static checks
            self._check_protocol(parsed, result)
            self._check_domain(parsed, result)
            self._check_tld(parsed, result)
            self._check_url_length(parsed, result)
            self._check_suspicious_patterns(url, result)
            self._check_phishing_indicators(url, parsed, result)
            self._check_malware_file_patterns(url, result)
            self._check_subdomain(parsed, result)
            self._check_port(parsed, result)
            self._check_url_encoding(url, result)
            self._check_redirect_params(url, result)

            # SSL
            self._check_ssl(parsed, result)

            # Reputation
            self._check_domain_reputation(parsed, result)

            # Deep scan
            if deep_scan and HAS_REQUESTS:
                self._deep_scan(url, parsed, result)

        except Exception as e:
            self._add_finding(result, ThreatFinding(
                CAT_NETWORK, "Analysis Error", "low",
                f"An error occurred during analysis: {str(e)[:120]}",
                recommendation="Try scanning again.",
                risk_points=10,
            ))

        self._finalize(result, start_time)
        return result

    # ==========================================================
    # FINDING HELPER
    # ==========================================================

    def _add_finding(self, result, finding):
        f = finding.to_dict()
        result["findings"].append(f)
        result["risk_score"] += finding.risk_points

        sev = finding.severity
        if sev in result["finding_summary"]:
            result["finding_summary"][sev] += 1

        if finding.category not in result["categories_detected"]:
            result["categories_detected"].append(finding.category)

        # Legacy
        if sev in ("critical", "high"):
            result["threats"].append(f"{finding.name}: {finding.description}")
        elif sev == "medium":
            result["warnings"].append(f"{finding.name}: {finding.description}")
        elif sev == "low":
            result["warnings"].append(f"{finding.name}: {finding.description}")
        else:
            result["info"].append(f"{finding.name}: {finding.description}")

        if finding.recommendation:
            if finding.recommendation not in result["recommendations"]:
                result["recommendations"].append(finding.recommendation)

        if finding.category in (CAT_MALWARE, CAT_SCRIPT, CAT_CRYPTO):
            result["malware_indicators"].append(finding.name)
        if finding.category == CAT_PHISHING:
            result["phishing_indicators"].append(finding.name)

    # ==========================================================
    # URL PARSING
    # ==========================================================

    def _parse_url(self, url):
        if not url:
            return None
        if not url.startswith(("http://", "https://", "ftp://")):
            url = "https://" + url
        try:
            p = urllib.parse.urlparse(url)
            if not p.netloc:
                return None
            domain = p.netloc.lower().split(":")[0]
            return {
                "full_url": url,
                "scheme": p.scheme,
                "domain": domain,
                "netloc": p.netloc,
                "path": p.path,
                "query": p.query,
                "fragment": p.fragment,
                "port": p.port,
                "url_length": len(url),
                "path_depth": len([x for x in p.path.split("/") if x]),
                "query_params": len(urllib.parse.parse_qs(p.query)),
                "has_at_symbol": "@" in p.netloc,
                "subdomain_count": max(0, len(domain.split(".")) - 2),
            }
        except Exception:
            return None

    # ==========================================================
    # STATIC CHECKS — with detailed ThreatFindings
    # ==========================================================

    def _check_protocol(self, parsed, result):
        s = parsed["scheme"]
        if s == "https":
            self._add_finding(result, ThreatFinding(
                CAT_SSL, "HTTPS Protocol", "info",
                "Website uses HTTPS encrypted connection. Data transmitted "
                "between your browser and the server is encrypted, preventing "
                "eavesdropping and man-in-the-middle attacks.",
                evidence=f"Protocol: {s}",
                risk_points=0,
            ))
            result["analysis"]["ssl"]["protocol"] = "https"
        elif s == "http":
            self._add_finding(result, ThreatFinding(
                CAT_SSL, "Unencrypted HTTP", "medium",
                "Website uses plain HTTP without encryption. All data "
                "including passwords, personal information, and cookies "
                "are transmitted in plain text. Any network observer "
                "(ISP, public WiFi, attacker) can intercept this data.",
                evidence=f"Protocol: {s}",
                recommendation="Only enter sensitive information on HTTPS sites. "
                               "Look for the padlock icon in your browser.",
                risk_points=15,
            ))
            result["analysis"]["ssl"]["protocol"] = "http"
        elif s == "ftp":
            self._add_finding(result, ThreatFinding(
                CAT_SSL, "FTP Protocol", "medium",
                "Website uses FTP protocol which transmits data unencrypted. "
                "Credentials and files are sent in plain text.",
                evidence=f"Protocol: {s}",
                recommendation="Use SFTP or HTTPS alternatives.",
                risk_points=20,
            ))
        else:
            self._add_finding(result, ThreatFinding(
                CAT_STRUCTURE, "Unusual Protocol", "high",
                f"URL uses non-standard protocol '{s}'. This is unusual "
                "for legitimate websites and may indicate a malicious scheme.",
                evidence=f"Protocol: {s}",
                recommendation="Do not trust URLs with unusual protocols.",
                risk_points=30,
            ))

    def _check_domain(self, parsed, result):
        d = parsed["domain"]
        result["analysis"]["domain"]["name"] = d
        result["analysis"]["domain"]["length"] = len(d)

        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', d):
            self._add_finding(result, ThreatFinding(
                CAT_PHISHING, "IP Address as Domain", "high",
                "This URL uses a raw IP address instead of a domain name. "
                "Legitimate websites almost always use registered domain "
                "names. Phishing sites and malware distribution servers "
                "frequently use IP addresses to avoid domain-based "
                "blocking and to make tracking more difficult.",
                evidence=f"Domain: {d}",
                recommendation="Avoid entering credentials or downloading "
                               "files from IP-based URLs.",
                risk_points=30,
            ))
            result["analysis"]["domain"]["is_ip"] = True
        else:
            result["analysis"]["domain"]["is_ip"] = False

        if len(d) > 50:
            self._add_finding(result, ThreatFinding(
                CAT_STRUCTURE, "Abnormally Long Domain", "medium",
                f"The domain name is {len(d)} characters long, which is "
                "unusual. Attackers often use very long domain names to "
                "disguise the actual destination or to overwhelm users "
                "so they don't notice suspicious elements.",
                evidence=f"Domain: {d} ({len(d)} chars)",
                recommendation="Carefully inspect the full domain name.",
                risk_points=10,
            ))

        if d.count("-") > 3:
            self._add_finding(result, ThreatFinding(
                CAT_PHISHING, "Excessive Hyphens in Domain", "medium",
                f"The domain contains {d.count('-')} hyphens. Phishing "
                "sites commonly use hyphens to create domains that look "
                "similar to legitimate ones (e.g., 'paypal-secure-login.com').",
                evidence=f"Domain: {d}",
                recommendation="Check if this is the official domain of "
                               "the service you're trying to access.",
                risk_points=12,
            ))

        main = d.split(".")[0]
        digits = sum(c.isdigit() for c in main)
        if len(main) > 5 and digits > len(main) * 0.5:
            self._add_finding(result, ThreatFinding(
                CAT_STRUCTURE, "Numeric Domain Name", "low",
                "The domain name consists mostly of numbers. "
                "While not always malicious, auto-generated or randomly "
                "numbered domains are commonly used by botnets and "
                "temporary malicious infrastructure.",
                evidence=f"Domain: {d} ({digits} digits out of {len(main)} chars)",
                risk_points=8,
            ))

    def _check_tld(self, parsed, result):
        d = parsed["domain"]
        for tld in self.suspicious_tlds:
            if d.endswith(tld):
                self._add_finding(result, ThreatFinding(
                    CAT_REPUTATION, "Suspicious Top-Level Domain", "medium",
                    f"The domain uses the '{tld}' TLD which is heavily "
                    "abused by malicious actors. Free or cheap TLDs like "
                    f"'{tld}' are popular for phishing, malware, and spam "
                    "because they can be registered anonymously at low cost.",
                    evidence=f"TLD: {tld}",
                    recommendation=f"Be extra cautious with '{tld}' domains. "
                                   "Verify the site's legitimacy independently.",
                    risk_points=15,
                ))
                result["analysis"]["domain"]["suspicious_tld"] = True
                return
        result["analysis"]["domain"]["suspicious_tld"] = False

    def _check_url_length(self, parsed, result):
        ln = parsed["url_length"]
        result["analysis"]["url_structure"]["total_length"] = ln
        if ln > 200:
            self._add_finding(result, ThreatFinding(
                CAT_STRUCTURE, "Excessively Long URL", "low",
                f"This URL is {ln} characters long. Very long URLs can "
                "hide malicious parameters, obfuscate the true destination, "
                "or contain encoded payloads. They may also overflow "
                "security tools that truncate URLs.",
                evidence=f"URL length: {ln} characters",
                risk_points=10,
            ))

    def _check_suspicious_patterns(self, url, result):
        for pattern, desc in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                self._add_finding(result, ThreatFinding(
                    CAT_STRUCTURE, f"Suspicious Pattern: {desc}", "low",
                    f"The URL contains a suspicious pattern: {desc}. "
                    "This type of pattern is commonly found in malicious "
                    "URLs used for phishing, malware delivery, or "
                    "exploit attempts.",
                    evidence=f"Pattern: {pattern}",
                    risk_points=7,
                ))

    def _check_phishing_indicators(self, url, parsed, result):
        path_query = (parsed["path"] + parsed["query"]).lower()
        domain = parsed["domain"]

        for brand in self.brand_names:
            if brand in path_query and brand not in domain:
                self._add_finding(result, ThreatFinding(
                    CAT_PHISHING, f"Brand Impersonation: {brand.title()}", "critical",
                    f"The URL references '{brand}' in its path but the "
                    f"domain is '{domain}', not the official {brand.title()} "
                    "domain. This is a strong indicator of a phishing attack "
                    "designed to steal your credentials by imitating a "
                    "trusted service.",
                    evidence=f"Brand '{brand}' found in path, domain is '{domain}'",
                    recommendation=f"Do NOT enter any credentials. "
                                   f"Go directly to {brand}.com instead.",
                    risk_points=25,
                ))

        kw_found = [kw for kw in self.phishing_keywords if kw in path_query]
        if len(kw_found) >= 3:
            self._add_finding(result, ThreatFinding(
                CAT_PHISHING, "Multiple Phishing Keywords", "medium",
                f"The URL contains {len(kw_found)} keywords commonly "
                "associated with phishing: " +
                ", ".join(kw_found[:6]) + ". "
                "Phishing URLs often include words like 'login', 'verify', "
                "'account', and 'secure' to create a sense of urgency.",
                evidence=f"Keywords: {', '.join(kw_found[:6])}",
                recommendation="Verify the URL by going to the official "
                               "website directly through your browser.",
                risk_points=len(kw_found) * 4,
            ))
        result["analysis"]["content"]["phishing_keywords"] = kw_found

        if parsed["has_at_symbol"]:
            self._add_finding(result, ThreatFinding(
                CAT_PHISHING, "URL Contains @ Symbol", "high",
                "The URL contains an '@' symbol in the authority section. "
                "This is a well-known URL obfuscation technique where "
                "everything before the '@' is ignored by the browser. "
                "For example, 'http://google.com@evil.com' actually goes "
                "to evil.com, not google.com.",
                evidence=f"Netloc: {parsed['netloc']}",
                recommendation="Do NOT click this URL. The apparent domain "
                               "is not the real destination.",
                risk_points=25,
            ))

    def _check_malware_file_patterns(self, url, result):
        url_lower = url.lower()
        for pattern, desc in self.malware_file_patterns:
            if re.search(pattern, url_lower):
                self._add_finding(result, ThreatFinding(
                    CAT_MALWARE, f"Malware Pattern: {desc}", "high",
                    f"The URL matches a known malware distribution pattern: "
                    f"{desc}. Downloading files from untrusted sources is "
                    "one of the most common ways to get infected with "
                    "viruses, ransomware, and trojans.",
                    evidence=f"Pattern matched: {pattern}",
                    recommendation="Do NOT download any files from this URL. "
                                   "If you need the software, get it from "
                                   "the official website.",
                    risk_points=12,
                ))

    def _check_subdomain(self, parsed, result):
        c = parsed["subdomain_count"]
        result["analysis"]["domain"]["subdomain_count"] = c
        if c > 3:
            self._add_finding(result, ThreatFinding(
                CAT_STRUCTURE, "Excessive Subdomains", "medium",
                f"The URL has {c} subdomains. Excessive subdomains "
                "are used to create convincing-looking URLs that appear "
                "to belong to trusted organizations. For example: "
                "'secure.login.paypal.evil.com' looks like PayPal "
                "but is actually hosted on evil.com.",
                evidence=f"Domain: {parsed['domain']} ({c} subdomains)",
                recommendation="Always check the main domain (the part "
                               "just before .com/.org/etc).",
                risk_points=10,
            ))

    def _check_port(self, parsed, result):
        port = parsed["port"]
        if port and port not in [80, 443, 8080, 8443]:
            self._add_finding(result, ThreatFinding(
                CAT_NETWORK, "Non-Standard Port", "low",
                f"The URL specifies port {port}. Standard web traffic "
                "uses ports 80 (HTTP) and 443 (HTTPS). Non-standard "
                "ports may indicate a server running unofficial services "
                "or an attempt to bypass security filters.",
                evidence=f"Port: {port}",
                risk_points=8,
            ))
            result["analysis"]["url_structure"]["non_standard_port"] = True
        else:
            result["analysis"]["url_structure"]["non_standard_port"] = False

    def _check_url_encoding(self, url, result):
        enc = url.count("%")
        result["analysis"]["url_structure"]["encoded_chars"] = enc
        if enc > 5:
            self._add_finding(result, ThreatFinding(
                CAT_STRUCTURE, "Heavy URL Encoding", "low",
                f"The URL contains {enc} percent-encoded characters. "
                "While encoding is normal for special characters, "
                "excessive encoding is used to hide the true content "
                "of URLs from users and security tools.",
                evidence=f"Encoded characters: {enc}",
                risk_points=8,
            ))

    def _check_redirect_params(self, url, result):
        redirect_keys = [
            "redirect", "url", "next", "return",
            "goto", "rurl", "dest", "continue"
        ]
        url_lower = url.lower()
        for key in redirect_keys:
            if f"{key}=http" in url_lower:
                self._add_finding(result, ThreatFinding(
                    CAT_REDIRECT, "Open Redirect Parameter", "medium",
                    f"The URL contains a '{key}' parameter pointing to "
                    "another website. Open redirects can be exploited to "
                    "send users to malicious sites while the initial URL "
                    "appears to belong to a trusted domain.",
                    evidence=f"Redirect parameter: {key}",
                    recommendation="Be cautious — you may be redirected "
                                   "to a different website than expected.",
                    risk_points=12,
                ))
                result["analysis"]["content"]["has_redirect_param"] = True
                return
        result["analysis"]["content"]["has_redirect_param"] = False

    # ==========================================================
    # SSL CHECK
    # ==========================================================

    def _check_ssl(self, parsed, result):
        if parsed["scheme"] != "https":
            result["analysis"]["ssl"]["valid"] = False
            result["analysis"]["ssl"]["checked"] = False
            return

        domain = parsed["domain"]
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(), server_hostname=domain
            ) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()

                issuer = dict(
                    x[0] for x in cert.get("issuer", [])
                ).get("organizationName", "Unknown")
                subject = dict(
                    x[0] for x in cert.get("subject", [])
                ).get("commonName", "Unknown")
                expires = cert.get("notAfter", "Unknown")

                result["analysis"]["ssl"].update({
                    "valid": True, "checked": True,
                    "issuer": issuer, "subject": subject,
                    "expires": expires,
                    "san": [e[1] for e in cert.get("subjectAltName", [])][:10],
                })

                self._add_finding(result, ThreatFinding(
                    CAT_SSL, "Valid SSL Certificate", "info",
                    f"The website has a valid SSL certificate issued by "
                    f"'{issuer}'. This means the connection is encrypted "
                    "and the identity of the server has been verified by "
                    "a trusted Certificate Authority.",
                    evidence=f"Issuer: {issuer}, Expires: {expires}",
                    risk_points=0,
                ))

                if issuer == subject:
                    self._add_finding(result, ThreatFinding(
                        CAT_SSL, "Self-Signed Certificate", "medium",
                        "The SSL certificate is self-signed (not issued by "
                        "a trusted CA). Self-signed certificates provide "
                        "encryption but do NOT verify the server's identity. "
                        "Man-in-the-middle attacks are possible.",
                        evidence=f"Issuer = Subject = {issuer}",
                        recommendation="Do not enter sensitive data on "
                                       "sites with self-signed certificates.",
                        risk_points=15,
                    ))

        except ssl.SSLCertVerificationError as e:
            self._add_finding(result, ThreatFinding(
                CAT_SSL, "Invalid SSL Certificate", "high",
                "The website's SSL certificate failed verification. "
                "This could mean the certificate is expired, issued "
                "for a different domain, self-signed, or has been "
                "tampered with. This is a strong security concern.",
                evidence=str(e)[:150],
                recommendation="Do NOT proceed to this website. "
                               "Your connection is not secure.",
                risk_points=25,
            ))
            result["analysis"]["ssl"]["valid"] = False
            result["analysis"]["ssl"]["checked"] = True

        except (socket.timeout, socket.gaierror,
                ConnectionRefusedError, OSError):
            result["analysis"]["ssl"]["valid"] = None
            result["analysis"]["ssl"]["checked"] = False

        except Exception:
            result["analysis"]["ssl"]["valid"] = None
            result["analysis"]["ssl"]["checked"] = False

    # ==========================================================
    # DOMAIN REPUTATION
    # ==========================================================

    def _check_domain_reputation(self, parsed, result):
        domain = parsed["domain"]
        for trusted in self.trusted_domains:
            if domain == trusted or domain.endswith("." + trusted):
                self._add_finding(result, ThreatFinding(
                    CAT_REPUTATION, "Trusted Domain", "info",
                    f"'{domain}' is recognized as a trusted, well-known "
                    "domain with established reputation.",
                    evidence=f"Matched trusted: {trusted}",
                    risk_points=-20,
                ))
                result["analysis"]["reputation"]["trusted"] = True
                result["analysis"]["reputation"]["category"] = "trusted"
                return

        result["analysis"]["reputation"]["trusted"] = False
        result["analysis"]["reputation"]["category"] = "unknown"

        try:
            ip = socket.gethostbyname(domain)
            result["analysis"]["domain"]["resolved_ip"] = ip

            private_ranges = [
                r'^10\.', r'^172\.(1[6-9]|2[0-9]|3[01])\.',
                r'^192\.168\.', r'^127\.', r'^0\.'
            ]
            for pr in private_ranges:
                if re.match(pr, ip):
                    self._add_finding(result, ThreatFinding(
                        CAT_NETWORK, "Private IP Resolution", "high",
                        f"The domain resolves to a private IP address ({ip}). "
                        "Public websites should not resolve to private addresses. "
                        "This could indicate DNS poisoning, a local attack, "
                        "or a misconfigured phishing server.",
                        evidence=f"Resolved IP: {ip}",
                        recommendation="Do not trust this website.",
                        risk_points=15,
                    ))
                    break
        except socket.gaierror:
            self._add_finding(result, ThreatFinding(
                CAT_NETWORK, "DNS Resolution Failed", "medium",
                f"The domain '{domain}' could not be resolved via DNS. "
                "This may mean the domain doesn't exist, has been taken "
                "down, or DNS is being blocked.",
                evidence=f"Domain: {domain}",
                risk_points=20,
            ))
            result["analysis"]["domain"]["resolved_ip"] = None

    # ==========================================================
    # DEEP SCAN
    # ==========================================================

    def _deep_scan(self, url, parsed, result):
        if not HAS_REQUESTS:
            return

        result["analysis"]["content"]["deep_scan"] = True

        try:
            resp = self.session.get(
                parsed["full_url"], timeout=10,
                allow_redirects=True, stream=True
            )

            cl = resp.headers.get("Content-Length")
            if cl and int(cl) > 5_000_000:
                self._add_finding(result, ThreatFinding(
                    CAT_MALWARE, "Large File Download", "medium",
                    "The page serves a very large file (>5MB) which may "
                    "indicate an automatic file download attempt.",
                    evidence=f"Content-Length: {cl}",
                    recommendation="Do not download files from untrusted URLs.",
                    risk_points=10,
                ))
                return

            content = resp.text[:2_000_000]

            self._analyze_headers(resp, result)
            self._analyze_redirects(resp, parsed, result)
            self._analyze_html(content, result)
            self._detect_malicious_scripts(content, result)
            self._detect_cryptominers(content, result)
            self._detect_hidden_iframes(content, result)
            self._detect_suspicious_forms(content, parsed, result)
            self._detect_obfuscation(content, result)
            self._detect_drive_by(content, result)
            self._analyze_external_resources(content, parsed, result)
            self._detect_phishing_page(content, parsed, result)

        except requests.exceptions.SSLError:
            self._add_finding(result, ThreatFinding(
                CAT_SSL, "SSL Connection Error", "high",
                "Could not establish a secure SSL connection to the website.",
                recommendation="Do not proceed — connection is not secure.",
                risk_points=20,
            ))
        except requests.exceptions.ConnectionError:
            self._add_finding(result, ThreatFinding(
                CAT_NETWORK, "Connection Failed", "low",
                "Could not connect to the website. The server may be down.",
                risk_points=5,
            ))
        except requests.exceptions.Timeout:
            self._add_finding(result, ThreatFinding(
                CAT_NETWORK, "Connection Timeout", "low",
                "The website took too long to respond (>10s).",
                risk_points=5,
            ))
        except requests.exceptions.TooManyRedirects:
            self._add_finding(result, ThreatFinding(
                CAT_REDIRECT, "Redirect Loop", "high",
                "The URL caused too many redirects, indicating a possible "
                "redirect loop attack designed to waste resources or "
                "confuse security tools.",
                recommendation="Avoid this URL.",
                risk_points=25,
            ))
        except Exception as e:
            pass

    def _analyze_headers(self, resp, result):
        headers = resp.headers
        h_info = {
            "status_code": resp.status_code,
            "content_type": headers.get("Content-Type", "unknown"),
            "server": headers.get("Server", "unknown"),
        }

        security_headers = {
            "X-Frame-Options": (
                "Clickjacking protection",
                "Prevents the page from being embedded in iframes on other "
                "sites, protecting against clickjacking attacks."
            ),
            "X-Content-Type-Options": (
                "MIME sniffing protection",
                "Prevents browsers from interpreting files as different "
                "MIME types, blocking MIME-based attacks."
            ),
            "Content-Security-Policy": (
                "Content Security Policy",
                "Controls which resources the browser is allowed to load, "
                "preventing XSS and data injection attacks."
            ),
            "Strict-Transport-Security": (
                "HTTP Strict Transport Security",
                "Forces browsers to only use HTTPS, preventing protocol "
                "downgrade attacks."
            ),
            "X-XSS-Protection": (
                "XSS Filter",
                "Enables the browser's built-in XSS filtering."
            ),
            "Referrer-Policy": (
                "Referrer Policy",
                "Controls how much referrer information is sent with requests."
            ),
        }

        present = []
        missing = []
        for header, (short, desc) in security_headers.items():
            if header.lower() in {k.lower() for k in headers.keys()}:
                present.append(header)
            else:
                missing.append(header)

        h_info["security_headers_present"] = present
        h_info["security_headers_missing"] = missing

        if len(missing) >= 4:
            missing_names = ", ".join(missing[:4])
            self._add_finding(result, ThreatFinding(
                CAT_HEADERS, "Missing Security Headers", "medium",
                f"The website is missing {len(missing)} important security "
                f"headers: {missing_names}. "
                "Without these headers, users are more vulnerable to "
                "clickjacking, XSS, and MIME-type attacks.",
                evidence=f"Missing: {', '.join(missing)}",
                recommendation="Well-maintained sites implement security headers.",
                risk_points=8,
            ))
        elif len(present) >= 4:
            self._add_finding(result, ThreatFinding(
                CAT_HEADERS, "Good Security Headers", "info",
                f"The website has {len(present)} security headers configured, "
                "indicating good security practices.",
                evidence=f"Present: {', '.join(present)}",
                risk_points=-5,
            ))

        result["analysis"]["headers"] = h_info

    def _analyze_redirects(self, resp, parsed, result):
        chain = [{"url": r.url, "status": r.status_code}
                 for r in resp.history]
        chain.append({"url": resp.url, "status": resp.status_code})

        result["analysis"]["redirects"] = {
            "count": len(resp.history),
            "chain": chain,
            "final_url": resp.url,
        }

        if len(resp.history) > 3:
            self._add_finding(result, ThreatFinding(
                CAT_REDIRECT, "Long Redirect Chain", "medium",
                f"The URL goes through {len(resp.history)} redirects before "
                "reaching the final page. Long redirect chains are used "
                "to obfuscate the final destination and bypass security filters.",
                evidence=f"Redirects: {len(resp.history)}",
                risk_points=8,
            ))

        if resp.history:
            orig = self._parse_url(resp.history[0].url)
            final = self._parse_url(resp.url)
            if orig and final and orig["domain"] != final["domain"]:
                self._add_finding(result, ThreatFinding(
                    CAT_REDIRECT, "Cross-Domain Redirect", "medium",
                    f"The URL redirected from '{orig['domain']}' to "
                    f"'{final['domain']}'. Cross-domain redirects can be "
                    "used to trick users into visiting malicious sites.",
                    evidence=f"{orig['domain']} → {final['domain']}",
                    risk_points=10,
                ))

    def _analyze_html(self, content, result):
        if not HAS_BS4:
            result["analysis"]["content"]["parser"] = "regex_only"
            return

        try:
            soup = BeautifulSoup(content, "html.parser")

            title = (soup.title.string.strip()
                     if soup.title and soup.title.string else "No title")
            meta_tag = soup.find("meta", attrs={"name": "description"})
            meta_desc = meta_tag.get("content", "")[:200] if meta_tag else ""

            scripts = soup.find_all("script")
            ext_scripts = [s.get("src") for s in scripts if s.get("src")]
            inline_scripts = [
                s.string for s in scripts
                if s.string and len(s.string.strip()) > 10
            ]

            links = soup.find_all("a", href=True)
            forms = soup.find_all("form")
            iframes = soup.find_all("iframe")
            inputs = soup.find_all("input")
            pw_fields = [
                i for i in inputs if i.get("type", "").lower() == "password"
            ]

            result["analysis"]["metadata"] = {
                "title": title, "description": meta_desc,
            }
            result["analysis"]["scripts"] = {
                "total": len(scripts), "external": len(ext_scripts),
                "inline": len(inline_scripts),
                "external_sources": ext_scripts[:20],
            }
            result["analysis"]["forms"] = {
                "total": len(forms),
                "has_password_field": len(pw_fields) > 0,
                "password_fields": len(pw_fields),
            }
            result["analysis"]["iframes"] = {
                "total": len(iframes),
                "sources": [f.get("src", "no-src") for f in iframes][:10],
            }
            result["analysis"]["content"]["links"] = len(links)
            result["analysis"]["content"]["inputs"] = len(inputs)

        except Exception:
            pass

    def _detect_malicious_scripts(self, content, result):
        found = []
        for pattern, desc in self.malicious_js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                found.append({"pattern": desc, "count": len(matches)})
                self._add_finding(result, ThreatFinding(
                    CAT_SCRIPT, f"Malicious Script: {desc}", "critical",
                    f"Detected malicious JavaScript pattern: {desc}. "
                    "This technique is commonly used by malware to "
                    "execute hidden code, steal data, or download "
                    "additional malicious payloads.",
                    evidence=f"Found {len(matches)} occurrence(s)",
                    recommendation="Leave this website immediately. "
                                   "Do not interact with any elements.",
                    risk_points=12,
                ))

        result["analysis"]["scripts"]["malicious_patterns"] = found

    def _detect_cryptominers(self, content, result):
        for pattern, desc in self.cryptominer_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                self._add_finding(result, ThreatFinding(
                    CAT_CRYPTO, f"Cryptominer: {desc}", "critical",
                    f"Detected cryptocurrency miner: {desc}. "
                    "This website is using your CPU to mine cryptocurrency "
                    "without your consent. This slows down your device, "
                    "increases electricity consumption, and can cause "
                    "hardware damage from overheating.",
                    evidence=f"Miner detected: {desc}",
                    recommendation="Close this website immediately. "
                                   "Consider using a miner-blocking extension.",
                    risk_points=30,
                ))
                result["analysis"]["scripts"]["cryptominer_detected"] = True
                return
        result["analysis"]["scripts"]["cryptominer_detected"] = False

    def _detect_hidden_iframes(self, content, result):
        patterns = [
            r'<iframe[^>]+style\s*=\s*["\'][^"\']*(?:display\s*:\s*none|'
            r'visibility\s*:\s*hidden|width\s*:\s*[01]px|height\s*:\s*[01]px)',
            r'<iframe[^>]+(?:width|height)\s*=\s*["\']?[01]["\']?',
        ]
        count = 0
        for pat in patterns:
            count += len(re.findall(pat, content, re.IGNORECASE))

        result["analysis"]["iframes"]["hidden_count"] = count
        if count:
            self._add_finding(result, ThreatFinding(
                CAT_MALWARE, "Hidden Iframes Detected", "critical",
                f"Found {count} hidden iframe(s) on this page. "
                "Hidden iframes (zero-size or invisible) are the primary "
                "delivery mechanism for drive-by download attacks. They "
                "load malicious content from other servers without the "
                "user's knowledge.",
                evidence=f"{count} hidden iframe(s)",
                recommendation="Leave immediately. Run an antivirus scan "
                               "if you visited this page.",
                risk_points=count * 15,
            ))

    def _detect_suspicious_forms(self, content, parsed, result):
        if not HAS_BS4:
            return
        try:
            soup = BeautifulSoup(content, "html.parser")
            suspicious = []
            for form in soup.find_all("form"):
                action = form.get("action", "")
                inputs = form.find_all("input")
                has_pw = any(
                    i.get("type", "").lower() == "password" for i in inputs
                )

                if has_pw and action.startswith("http"):
                    ad = self._parse_url(action)
                    if ad and ad["domain"] != parsed["domain"]:
                        suspicious.append({
                            "action": action[:100],
                            "target": ad["domain"],
                        })
                        self._add_finding(result, ThreatFinding(
                            CAT_PHISHING,
                            "Credential Harvesting Form",
                            "critical",
                            f"A login form on this page sends credentials "
                            f"to '{ad['domain']}' which is a different "
                            f"domain than '{parsed['domain']}'. This is "
                            "a classic phishing technique to steal passwords.",
                            evidence=f"Form action: {action[:100]}",
                            recommendation="Do NOT enter any credentials.",
                            risk_points=20,
                        ))

                if (has_pw and
                        not result["analysis"]["reputation"].get("trusted")):
                    suspicious.append({
                        "action": action[:100] or "self",
                        "reason": "Password form on untrusted domain",
                    })

            result["analysis"]["forms"]["suspicious"] = suspicious
        except Exception:
            pass

    def _detect_obfuscation(self, content, result):
        indicators = 0
        details = []

        b64 = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', content)
        if len(b64) > 3:
            indicators += 1
            details.append(f"{len(b64)} long base64 strings")

        hx = re.findall(r'(?:\\x[0-9a-fA-F]{2}){10,}', content)
        if hx:
            indicators += 1
            details.append(f"{len(hx)} hex-encoded strings")

        uni = re.findall(r'(?:\\u[0-9a-fA-F]{4}){10,}', content)
        if uni:
            indicators += 1
            details.append(f"{len(uni)} unicode-encoded strings")

        evals = len(re.findall(r'\beval\s*\(', content))
        if evals > 2:
            indicators += 1
            details.append(f"{evals} eval() calls")

        dw = len(re.findall(r'document\.write\s*\(', content))
        if dw > 3:
            indicators += 1
            details.append(f"{dw} document.write() calls")

        fcc = len(re.findall(r'String\.fromCharCode', content))
        if fcc > 5:
            indicators += 1
            details.append(f"{fcc} fromCharCode calls")

        result["analysis"]["scripts"]["obfuscation_score"] = indicators

        if indicators >= 3:
            self._add_finding(result, ThreatFinding(
                CAT_SCRIPT, "Heavy Code Obfuscation", "high",
                f"Detected {indicators} code obfuscation techniques: "
                f"{'; '.join(details)}. Heavy obfuscation is used to "
                "hide malicious payloads from antivirus engines and "
                "security researchers.",
                evidence=f"Indicators: {indicators}",
                recommendation="This site likely contains hidden malicious code.",
                risk_points=indicators * 8,
            ))
        elif indicators >= 1:
            self._add_finding(result, ThreatFinding(
                CAT_SCRIPT, "Code Obfuscation Detected", "medium",
                f"Detected {indicators} obfuscation indicator(s): "
                f"{'; '.join(details)}.",
                evidence=f"Indicators: {indicators}",
                risk_points=indicators * 4,
            ))

    def _detect_drive_by(self, content, result):
        checks = [
            (r'<meta[^>]+http-equiv\s*=\s*["\']refresh["\'][^>]+url\s*='
             r'[^"\']*\.(exe|msi|apk|dmg|zip|rar)',
             "Auto-redirect to executable file",
             "The page automatically redirects to download a potentially "
             "malicious executable file."),
            (r'window\.location\s*=\s*["\'][^"\']*\.(exe|msi|apk|dmg|zip|rar)',
             "JavaScript redirect to executable",
             "JavaScript code redirects the browser to download an "
             "executable file."),
            (r'<a[^>]+download[^>]+\.(exe|msi|apk|dmg)',
             "Auto-download link for executable",
             "A link with the 'download' attribute attempts to "
             "automatically download an executable file."),
            (r'<iframe[^>]+src\s*=\s*["\'][^"\']*\.(exe|msi|apk|dmg)',
             "Iframe loading executable",
             "A hidden iframe attempts to load an executable file."),
        ]

        indicators = []
        for pattern, name, desc in checks:
            if re.search(pattern, content, re.IGNORECASE):
                indicators.append(name)
                self._add_finding(result, ThreatFinding(
                    CAT_MALWARE, f"Drive-By Download: {name}", "critical",
                    desc + " Drive-by downloads install malware on your "
                    "computer without your explicit consent, often exploiting "
                    "browser vulnerabilities.",
                    evidence=f"Pattern: {name}",
                    recommendation="Close this page immediately. Run a full "
                                   "antivirus scan on your system.",
                    risk_points=18,
                ))

        result["analysis"]["content"]["drive_by_indicators"] = indicators

    def _analyze_external_resources(self, content, parsed, result):
        ext_domains = set()
        for domain in re.findall(
            r'(?:src|href)\s*=\s*["\']https?://([^/"\']+)',
            content, re.IGNORECASE
        ):
            d = domain.lower().split(":")[0]
            if d != parsed["domain"]:
                ext_domains.add(d)

        result["analysis"]["content"]["external_domains"] = list(ext_domains)[:30]
        result["analysis"]["content"]["external_domain_count"] = len(ext_domains)

        if len(ext_domains) > 20:
            self._add_finding(result, ThreatFinding(
                CAT_CONTENT, "Excessive External Resources", "low",
                f"The page loads resources from {len(ext_domains)} "
                "different external domains, which may indicate "
                "compromised or ad-heavy content.",
                evidence=f"External domains: {len(ext_domains)}",
                risk_points=5,
            ))

        for ed in ext_domains:
            for tld in self.suspicious_tlds:
                if ed.endswith(tld):
                    self._add_finding(result, ThreatFinding(
                        CAT_CONTENT,
                        f"Suspicious External Resource: {ed}",
                        "medium",
                        f"The page loads resources from '{ed}' which uses "
                        f"the suspicious TLD '{tld}'. This external resource "
                        "could be delivering malware or tracking scripts.",
                        evidence=f"External domain: {ed}",
                        risk_points=8,
                    ))
                    break

    def _detect_phishing_page(self, content, parsed, result):
        content_lower = content.lower()
        score = 0
        indicators = []

        for brand in self.brand_names:
            if brand in content_lower and brand not in parsed["domain"]:
                count = content_lower.count(brand)
                if count > 3:
                    score += 2
                    indicators.append(
                        f"'{brand}' mentioned {count}x but not the real domain"
                    )

        urgency = [
            "immediately", "urgent", "suspended", "verify now",
            "confirm now", "act now", "limited time", "24 hours",
            "your account will be", "unauthorized access",
        ]
        uf = [w for w in urgency if w in content_lower]
        if len(uf) >= 2:
            score += 2
            indicators.append(f"Urgency language: {', '.join(uf[:3])}")

        cp = r'©\s*\d{4}\s*(?:' + '|'.join(self.brand_names) + r')'
        if re.search(cp, content_lower):
            if not result["analysis"]["reputation"].get("trusted"):
                score += 3
                indicators.append("Fake copyright notice")

        result["analysis"]["content"]["phishing_score"] = score
        result["analysis"]["content"]["phishing_page_indicators"] = indicators

        if score >= 5:
            self._add_finding(result, ThreatFinding(
                CAT_PHISHING, "Phishing Page Detected", "critical",
                "Multiple strong phishing indicators found on this page: " +
                "; ".join(indicators) + ". "
                "This page is designed to steal your personal information "
                "by impersonating a trusted organization.",
                evidence=f"Phishing score: {score}/10",
                recommendation="Do NOT enter any information. Close immediately.",
                risk_points=25,
            ))
        elif score >= 3:
            self._add_finding(result, ThreatFinding(
                CAT_PHISHING, "Possible Phishing Page", "high",
                "Several phishing indicators detected: " +
                "; ".join(indicators) + ".",
                evidence=f"Phishing score: {score}/10",
                recommendation="Exercise caution. Do not enter credentials.",
                risk_points=12,
            ))

    # ==========================================================
    # FINALIZE
    # ==========================================================

    def _finalize(self, result, start_time):
        score = min(100, max(0, result["risk_score"]))
        result["risk_score"] = score

        if score >= 70:
            result["risk_level"] = "critical"
            result["safe"] = False
        elif score >= 50:
            result["risk_level"] = "high"
            result["safe"] = False
        elif score >= 30:
            result["risk_level"] = "medium"
            result["safe"] = False
        elif score >= 15:
            result["risk_level"] = "low"
            result["safe"] = True
        else:
            result["risk_level"] = "safe"
            result["safe"] = True

        # Sort findings by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        result["findings"].sort(
            key=lambda f: sev_order.get(f["severity"], 5)
        )

        # Build report summary
        result["report"]["total_findings"] = len(result["findings"])
        result["report"]["finding_summary"] = result["finding_summary"]
        result["report"]["categories"] = result["categories_detected"]
        result["report"]["risk_score"] = score
        result["report"]["risk_level"] = result["risk_level"]
        result["report"]["safe"] = result["safe"]

        result["scan_duration_ms"] = int((time.time() - start_time) * 1000)
        result["url_hash"] = hashlib.sha256(
            result["url"].encode()
        ).hexdigest()[:16]


analyzer = URLAnalyzer()


def analyze_url(url, deep_scan=True):
    return analyzer.analyze(url, deep_scan)