# Mewtwo — Recon Module

The recon module lives in `mewtwo/modules/recon/` and is the first phase of every
engagement. It builds the raw dataset that every later phase depends on.

---

## subdomains.py

### Passive enumeration

```python
async def enumerate_passive(domain: str) -> list[str]:
```

Two sources:

**crt.sh** — queries the certificate transparency log database. Every time a TLS
certificate is issued for a domain, it's publicly logged. crt.sh exposes this as a
JSON API:
```
https://crt.sh/?q=%.example.com&output=json
```
The `%` wildcard matches any subdomain. Each entry has a `name_value` field which can
contain multiple subdomains (newline-separated). The code strips `*.` prefixes from
wildcard certs and deduplicates everything into a set.

**HackerTarget** — queries their `hostsearch` API which aggregates DNS data:
```
https://api.hackertarget.com/hostsearch/?q=example.com
```
Returns `hostname,ip` lines. We only take the hostname column.

Both are wrapped in try/except so a single source failing doesn't abort the whole run.

### Active enumeration

```python
async def enumerate_active(domain: str) -> list[str]:
    if not tool_available("subfinder"):
        return []
    _, stdout, _ = await run("subfinder", "-d", domain, "-silent", timeout=120)
```

`tool_available` is a `shutil.which` wrapper — checks if `subfinder` is on PATH.
If it isn't, silently skips rather than crashing. The `-silent` flag suppresses
subfinder's banner so we only get raw hostnames on stdout.

### Alive probing

```python
async def probe_alive(hostname: str) -> tuple[bool, int | None]:
    for scheme in ("https", "http"):
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
                resp = await client.get(f"{scheme}://{hostname}")
                return True, resp.status_code
        except Exception:
            continue
    return False, None
```

Tries HTTPS first (more common), falls back to HTTP. `verify=False` skips TLS
certificate validation — common on bug bounty targets with self-signed or expired certs.
`timeout=8` keeps the overall probe fast; a non-responding host wastes at most 8 seconds.

The concurrency is controlled with `asyncio.Semaphore(30)` — at most 30 hosts probed
simultaneously. Higher concurrency doesn't help much (network is the bottleneck) and
risks triggering rate limiting on the target.

---

## ports.py

```python
async def scan_ports(target_id, host, top_ports=1000) -> list[Port]:
    _, stdout, _ = await run(
        "nmap", "-sV", f"--top-ports={top_ports}", "-T4",
        "--open", "-oX", "-", host, timeout=300
    )
```

Flags:
- `-sV` — version detection (identifies what service is running on each port)
- `--top-ports=1000` — scan the 1000 most commonly used ports
- `-T4` — aggressive timing (faster scans, acceptable for authorised testing)
- `--open` — only show open ports
- `-oX -` — output XML to stdout for structured parsing

The output is parsed with `xml.etree.ElementTree`:
```python
for port_el in host_el.findall(".//port[@protocol]"):
    port_num = int(port_el.get("portid"))
    service_el = port_el.find("service")
    service_name = service_el.get("name", "") if service_el is not None else ""
    version = f"{service_el.get('product','')} {service_el.get('version','')}".strip()
```

XML is used rather than text output because it's unambiguous — nmap's text output
formats can vary between versions.

---

## tech.py

Fingerprinting works in two passes: headers then body.

```python
_SIGNATURES = [
    {"name": "Apache",   "category": "web_server",  "header": "server",       "pattern": re.compile(r"apache", re.I)},
    {"name": "Nginx",    "category": "web_server",  "header": "server",       "pattern": re.compile(r"nginx", re.I)},
    {"name": "PHP",      "category": "language",    "header": "x-powered-by", "pattern": re.compile(r"php", re.I)},
    {"name": "Django",   "category": "framework",   "header": "x-frame-options", "pattern": re.compile(r"SAMEORIGIN", re.I)},
    ...
]
```

For each signature, the code checks if the HTTP response header matches the regex:
```python
for sig in _SIGNATURES:
    header_val = resp.headers.get(sig["header"], "")
    if sig["pattern"].search(header_val):
        # version extraction: grab digits after the name
        version_match = re.search(r"[\d.]+", header_val)
```

Body signatures scan the HTML for framework-specific markers:
```python
_BODY_SIGNATURES = [
    {"name": "WordPress", "pattern": re.compile(r"wp-content|wp-includes", re.I)},
    {"name": "React",     "pattern": re.compile(r"__REACT_DEVTOOLS|react\.development", re.I)},
    {"name": "Swagger",   "pattern": re.compile(r"swagger-ui|Swagger UI", re.I)},
    ...
]
```

Deduplication by name ensures you don't get five `Nginx` entries from five different
pages on the same host.

---

## crawler.py

Implements **BFS** (Breadth-First Search) using a `deque` as the queue:

```python
queue: deque[tuple[str, int]] = deque([(seed_url, 0)])

while queue and len(results) < max_urls:
    batch = []
    while queue and len(batch) < concurrency:
        url, depth_level = queue.popleft()
        if url in visited:
            continue
        visited.add(url)
        batch.append((url, depth_level))

    tasks = [fetch(url, d) for url, d in batch]
    for new_links in await asyncio.gather(*tasks):
        queue.extend(new_links)
```

Each tuple in the queue is `(url, depth)`. When depth reaches the limit, `fetch`
returns an empty list (no further links added). `visited` is a set for O(1) lookup.

The `fetch` function extracts three things per page:
1. **URL parameters** — `parse_qs(parsed.query).keys()` gives the parameter names
2. **Forms** — regex extracts `<form action="...">` + `<input name="...">` elements
3. **Interesting headers** — security-relevant headers captured per URL

```python
_INTERESTING_HEADERS = {
    "server", "x-powered-by", "x-frame-options",
    "content-security-policy", "access-control-allow-origin",
    "strict-transport-security", ...
}
```

These headers are stored with each URL because they're needed by the surface mapper's
CORS and CSP heuristics.

Link normalisation strips fragments (`#section`) and rejects non-HTTP schemes:
```python
def _normalize(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return None
    return parsed._replace(fragment="").geturl()
```

---

## wayback.py

Queries the CDX API:
```
http://web.archive.org/cdx/search/cdx
  ?url=*.example.com
  &output=json
  &fl=original,statuscode,timestamp
  &collapse=urlkey       ← deduplicate by URL key (same URL, different params = same key)
  &limit=10000
  &filter=statuscode:200 ← only successful responses
```

The `collapse=urlkey` parameter is important — without it, you get millions of rows
for URLs that were archived thousands of times. `urlkey` is a SURT (Sort-friendly URI
Reordering Transform) of the URL that normalises it for comparison.

The first row of the response is always a header row `["original","statuscode","timestamp"]`
— the code skips it with `rows[1:]`.

Timestamp format is `YYYYMMDDHHmmss` — parsed with `strptime` and stored as
`discovered_at` so you can see how old each URL is.

Extensions filter:
```python
_SKIP_EXTENSIONS = {".png", ".jpg", ".css", ".woff", ".pdf", ".zip", ...}
```
Removes static assets — they add noise without attack surface value. JavaScript is
kept because `.js` files can contain API endpoints and secrets.

---

## js_analyzer.py

Scans JavaScript files for leaked secrets using regex:

```python
_PATTERNS = [
    ("api_key",     re.compile(r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']([^"\']{10,})["\']', re.I)),
    ("aws_key",     re.compile(r'AKIA[0-9A-Z]{16}')),
    ("jwt",         re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+')),
    ("private_key", re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ("endpoint",    re.compile(r'["\']/(api|v\d|rest|graphql)/[^"\'?\s]{3,}["\']', re.I)),
    ...
]
```

For each JS file found on a page, the analyzer:
1. Fetches the JS URL
2. Runs all patterns against the content
3. Assigns a confidence level (`high` for AWS keys with known format, `medium` for
   generic API key patterns)

`analyze_page_js` fetches the HTML first, extracts all `<script src="...">` tags,
then analyzes each `.js` file in parallel.

---

## runner.py

Orchestrates all steps:

```python
steps = {"subdomains", "ports", "tech", "urls", "js", "wayback"}
```

Step ordering matters:
1. **Subdomains first** — subsequent steps iterate over discovered hosts
2. **Ports** — only scans alive hosts (`is_alive = 1`), capped at 10 to avoid long scans
3. **Tech** — fingerprints alive hosts, capped at 20
4. **URLs** — crawl from the root domain seed
5. **Wayback** — harvest historical URLs
6. **JS** — analyze JS files on alive hosts, capped at 10

The `--only` flag on `mewtwo recon run` accepts a subset of these step names, letting
you re-run just one step without repeating everything.
