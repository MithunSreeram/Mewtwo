"""CVSS 3.1 calculator — score from metric components."""

from __future__ import annotations

from ...models.finding import CVSSVector


# CVSS 3.1 metric weights
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


def calculate_cvss(v: CVSSVector) -> CVSSVector:
    """Calculate CVSS 3.1 base score and vector string. Returns updated model."""
    av = _AV.get(v.attack_vector, 0.85)
    ac = _AC.get(v.attack_complexity, 0.77)
    pr = (
        _PR_CHANGED.get(v.privileges_required, 0.85)
        if v.scope == "C"
        else _PR_UNCHANGED.get(v.privileges_required, 0.85)
    )
    ui = _UI.get(v.user_interaction, 0.85)
    s = v.scope

    c = _CIA.get(v.confidentiality, 0.00)
    i = _CIA.get(v.integrity, 0.00)
    a = _CIA.get(v.availability, 0.00)

    # ISS
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    # Impact
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    # Exploitability
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    else:
        if s == "U":
            raw = min(impact + exploitability, 10)
        else:
            raw = min(1.08 * (impact + exploitability), 10)
        # Round up to 1 decimal
        score = round(raw * 10) / 10

    vector_string = (
        f"CVSS:3.1/AV:{v.attack_vector}/AC:{v.attack_complexity}/"
        f"PR:{v.privileges_required}/UI:{v.user_interaction}/"
        f"S:{v.scope}/C:{v.confidentiality}/I:{v.integrity}/A:{v.availability}"
    )

    return CVSSVector(
        attack_vector=v.attack_vector,
        attack_complexity=v.attack_complexity,
        privileges_required=v.privileges_required,
        user_interaction=v.user_interaction,
        scope=v.scope,
        confidentiality=v.confidentiality,
        integrity=v.integrity,
        availability=v.availability,
        score=score,
        vector_string=vector_string,
    )


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "critical"
    elif score >= 7.0:
        return "high"
    elif score >= 4.0:
        return "medium"
    elif score > 0:
        return "low"
    return "informational"


def interactive_cvss() -> CVSSVector:
    """Prompt user for CVSS metrics interactively via click."""
    import click

    click.echo("\nCVSS 3.1 Base Score Calculator\n")

    av = click.prompt("Attack Vector (N=Network A=Adjacent L=Local P=Physical)",
                      type=click.Choice(["N", "A", "L", "P"]), default="N")
    ac = click.prompt("Attack Complexity (L=Low H=High)",
                      type=click.Choice(["L", "H"]), default="L")
    pr = click.prompt("Privileges Required (N=None L=Low H=High)",
                      type=click.Choice(["N", "L", "H"]), default="N")
    ui = click.prompt("User Interaction (N=None R=Required)",
                      type=click.Choice(["N", "R"]), default="N")
    s = click.prompt("Scope (U=Unchanged C=Changed)",
                     type=click.Choice(["U", "C"]), default="U")
    c = click.prompt("Confidentiality Impact (N=None L=Low H=High)",
                     type=click.Choice(["N", "L", "H"]), default="N")
    i = click.prompt("Integrity Impact (N=None L=Low H=High)",
                     type=click.Choice(["N", "L", "H"]), default="N")
    a = click.prompt("Availability Impact (N=None L=Low H=High)",
                     type=click.Choice(["N", "L", "H"]), default="N")

    raw = CVSSVector(
        attack_vector=av, attack_complexity=ac, privileges_required=pr,
        user_interaction=ui, scope=s, confidentiality=c, integrity=i, availability=a,
    )
    return calculate_cvss(raw)
