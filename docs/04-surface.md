# Mewtwo — Attack Surface Mapping

The surface module converts raw recon data into structured, testable **attack vectors**.
It lives in `mewtwo/modules/surface/`.

---

## What Is an Attack Vector?

In this codebase, an `AttackVector` is a row in the `attack_vectors` table representing
one testable opportunity:

```python
class AttackVector(BaseModel):
    id: str
    target_id: str
    category: VectorCategory      # authentication | injection | ssrf | ...
    title: str                    # human-readable label
    description: str              # why this is interesting
    url: str                      # the endpoint to test
    parameters: list[str]         # parameter names to fuzz
    risk_rating: str              # critical | high | medium | low
    rationale: str                # reasoning for the rating
    source_recon_ids: list[str]   # which recon rows it was derived from
    checked: bool = False         # set to True after hunt runs against it
    finding_ids: list[str]        # findings discovered from this vector
```

The hunt runner loads unchecked vectors and dispatches checks against them. Once a
vector is checked, it's marked so you don't retest the same thing on the next run.

---

## heuristics.py

This is the largest single file in the codebase (326 lines). It contains deterministic
rules that convert recon rows into attack vectors.

The top-level function:
```python
def map_from_recon(target_id, urls, technologies, js_secrets, subdomains) -> list[AttackVector]:
    vectors = []
    vectors.extend(_check_urls(target_id, urls))
    vectors.extend(_check_technologies(target_id, technologies, urls))
    vectors.extend(_check_js_secrets(target_id, js_secrets))
    vectors.extend(_check_subdomains(target_id, subdomains))

    # Deduplicate by (category, url)
    seen = set()
    unique = []
    for v in vectors:
        key = (v.category, v.url)
        if key not in seen:
            seen.add(key)
            unique.append(v)
    return unique
```

Deduplication uses `(category, url)` as the key — the same URL can appear as both
an injection vector (if it has parameters) and an authorization vector (if it returns
403). Different categories = different rows.

### URL-based heuristics

The heuristics use compiled regexes for pattern matching:

```python
_LOGIN_PATTERNS   = re.compile(r"login|signin|sign-in|auth|sso|oauth|token|session", re.I)
_ADMIN_PATTERNS   = re.compile(r"admin|dashboard|manage|panel|backoffice|staff|internal", re.I)
_IDOR_PARAMS      = re.compile(r"\bid\b|user_id|account_id|order_id|invoice_id|uid|uuid", re.I)
_SSRF_PARAMS      = re.compile(r"url|uri|path|src|dest|target|proxy|fetch|callback", re.I)
_SQLI_PARAMS      = re.compile(r"search|query|q|filter|sort|order|id|page|limit|where", re.I)
_REDIRECT_PARAMS  = re.compile(r"redirect|return|next|url|goto|target|destination", re.I)
```

For each URL in the recon dataset:

```python
for url_row in urls:
    url = url_row.get("url", "")
    params = url_row.get("parameters", [])
    status = url_row.get("status_code", 200)

    # 403/401 endpoints — access control to test
    if status in (401, 403):
        vectors.append(AttackVector(
            category=VectorCategory.AUTHORIZATION,
            title=f"Restricted endpoint: {urlparse(url).path}",
            risk_rating="high",
            rationale="Endpoint returns 403/401 — test for authorization bypass"
        ))

    # Login/auth endpoints
    if _LOGIN_PATTERNS.search(url):
        vectors.append(AttackVector(
            category=VectorCategory.AUTHENTICATION,
            risk_rating="high",
            rationale="Authentication endpoint — test for bypass, bruteforce, and token issues"
        ))

    # Parameters that look like IDs → IDOR
    idor_params = [p for p in params if _IDOR_PARAMS.search(p)]
    if idor_params:
        vectors.append(AttackVector(
            category=VectorCategory.AUTHORIZATION,
            parameters=idor_params,
            risk_rating="high",
            rationale="Numeric ID parameter — test for IDOR"
        ))
```

### Technology-based heuristics

```python
def _check_technologies(target_id, technologies, urls) -> list[AttackVector]:
    for tech in technologies:
        name = tech.get("name", "").lower()
        host = tech.get("host", "")

        if "wordpress" in name:
            vectors += [
                # /wp-admin login, xmlrpc.php, /wp-json/wp/v2/users
                ...
            ]
        if "graphql" in name:
            vectors.append(AttackVector(
                category=VectorCategory.INJECTION,
                title="GraphQL introspection and injection",
                url=f"https://{host}/graphql",
                risk_rating="high"
            ))
        if "php" in name:
            # PHP-specific injection patterns
            ...
```

WordPress, GraphQL, Swagger, Django, Nginx, PHP, Apache, and several other stacks each
get their own heuristic block — adding vectors specific to known vulnerabilities in
those technologies.

### JS secret-based heuristics

```python
def _check_js_secrets(target_id, js_secrets) -> list[AttackVector]:
    for secret in js_secrets:
        kind = secret.get("secret_type", "")
        value = secret.get("value", "")
        source_url = secret.get("source_url", "")

        if kind == "endpoint":
            # JS file exposed an internal API path
            vectors.append(AttackVector(
                category=VectorCategory.INFO_DISCLOSURE,
                title=f"Exposed API endpoint in JS: {value}",
                url=value,
                risk_rating="medium"
            ))
        elif kind == "api_key":
            vectors.append(AttackVector(
                category=VectorCategory.INFO_DISCLOSURE,
                title="Hardcoded API key in JavaScript",
                risk_rating="high"
            ))
```

### Subdomain-based heuristics

```python
_DEV_PATTERNS  = re.compile(r"dev\.|staging\.|test\.|uat\.|qa\.", re.I)
_ADMIN_PATTERNS = re.compile(r"admin\.|internal\.|corp\.", re.I)

for sub in subdomains:
    if not sub.get("is_alive"):
        continue
    hostname = sub.get("hostname", "")

    if _DEV_PATTERNS.search(hostname):
        vectors.append(AttackVector(
            category=VectorCategory.CONFIGURATION,
            title=f"Dev/staging subdomain: {hostname}",
            risk_rating="medium",
            rationale="Dev environments often lack hardening present in production"
        ))
```

---

## mapper.py

```python
async def run_surface_map(target_id, db_path, use_ai=True) -> dict:
    db = get_db(db_path)
    repo = ReconRepository(db)
    surf = SurfaceRepository(db)

    # Load all recon data
    urls      = repo.urls_for(target_id)
    techs     = repo.techs_for(target_id)
    secrets   = repo.js_secrets_for(target_id)
    subdomains = repo.subdomains_for(target_id)

    # Deterministic heuristics
    vectors = heuristics.map_from_recon(target_id, urls, techs, secrets, subdomains)
    for v in vectors:
        surf.upsert_vector(v)

    # Optional AI expansion
    if use_ai:
        from ..ai.client import AIClient
        client = AIClient()
        recon_summary = {"urls": len(urls), "techs": [t["name"] for t in techs], ...}
        existing = [v.model_dump() for v in vectors]
        result = client.expand_attack_surface(recon_summary, existing, db_path)
        for av in result.get("vectors", []):
            # AI-generated vectors saved the same way
            surf.upsert_vector(AttackVector(...))
```

The AI expansion runs **after** heuristics, receives the existing vectors as context
("don't duplicate these"), and adds vectors that require attacker intuition beyond
simple pattern matching.

---

## SurfaceRepository

```python
def upsert_vector(self, vector: AttackVector) -> None:
    self.db["attack_vectors"].upsert({
        "id": vector.id,
        "target_id": vector.target_id,
        "category": vector.category.value,
        "title": vector.title,
        "parameters_json": json.dumps(vector.parameters),
        "checked": int(vector.checked),
        "finding_ids_json": json.dumps(vector.finding_ids),
        ...
    }, pk="id", alter=True)

def mark_checked(self, vector_id: str) -> None:
    self.db["attack_vectors"].update(vector_id, {"checked": 1})
```

`alter=True` in `upsert` tells sqlite-utils to add any missing columns automatically
— useful when new fields are added to the model without manually running migrations.
