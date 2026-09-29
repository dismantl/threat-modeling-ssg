import pytest

from ratm import scales


@pytest.mark.parametrize(
    ("impact", "likelihood", "expected"),
    [
        ("Low", "Very Low", 1),
        ("Medium", "Low", 4),
        ("High", "High", 12),
        ("High", None, None),
        (None, "Low", None),
        ("Critical", "Low", None),
        ("High", "Unlikely", None),
    ],
)
def test_risk_score(impact, likelihood, expected) -> None:
    assert scales.risk_score(impact, likelihood) == expected


def test_capec_severity_clamps_to_impact_scale() -> None:
    assert scales.CAPEC_SEVERITY_TO_IMPACT["Very High"] == "High"
    assert scales.CAPEC_SEVERITY_TO_IMPACT["Very Low"] == "Low"
    assert set(scales.CAPEC_SEVERITY_TO_IMPACT.values()) <= set(scales.IMPACT_SCORES)


def test_impact_order_covers_the_scale_and_unknown() -> None:
    assert list(scales.IMPACT_ORDER) == ["High", "Medium", "Low", scales.UNKNOWN]


def test_statuses() -> None:
    assert scales.DEFAULT_THREAT_STATUS in scales.THREAT_STATUSES
    assert "partially mitigated" in scales.THREAT_STATUSES
    assert "out of scope" in scales.THREAT_STATUSES
    assert scales.DEFAULT_MITIGATION_STATUS in scales.MITIGATION_STATUSES
    assert scales.MITIGATION_STATUSES == ("implemented", "optional", "proposed")
