"""CVSS 3.1 base-score tests against canonical NVD vectors."""

import pytest

from mewtwo.models.finding import CVSSVector
from mewtwo.modules.findings.cvss import calculate_cvss, score_to_severity


@pytest.mark.parametrize("metrics,expected", [
    # Full critical — the classic 9.8
    (dict(attack_vector="N", attack_complexity="L", privileges_required="N",
          user_interaction="N", scope="U", confidentiality="H", integrity="H",
          availability="H"), 9.8),
    # Reflected XSS canonical vector — 6.1
    (dict(attack_vector="N", attack_complexity="L", privileges_required="N",
          user_interaction="R", scope="C", confidentiality="L", integrity="L",
          availability="N"), 6.1),
    # Network DoS (availability only) — 7.5
    (dict(attack_vector="N", attack_complexity="L", privileges_required="N",
          user_interaction="N", scope="U", confidentiality="N", integrity="N",
          availability="H"), 7.5),
    # No impact — 0.0
    (dict(attack_vector="N", attack_complexity="L", privileges_required="N",
          user_interaction="N", scope="U", confidentiality="N", integrity="N",
          availability="N"), 0.0),
])
def test_known_scores(metrics, expected):
    result = calculate_cvss(CVSSVector(**metrics))
    assert result.score == expected


def test_vector_string_roundtrips():
    v = calculate_cvss(CVSSVector(
        attack_vector="N", attack_complexity="L", privileges_required="N",
        user_interaction="N", scope="U", confidentiality="H", integrity="H",
        availability="H",
    ))
    assert v.vector_string == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


@pytest.mark.parametrize("score,sev", [
    (9.8, "critical"), (9.0, "critical"), (7.5, "high"), (7.0, "high"),
    (6.1, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "informational"),
])
def test_score_to_severity(score, sev):
    assert score_to_severity(score) == sev
