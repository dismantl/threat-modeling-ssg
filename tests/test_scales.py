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


@pytest.mark.parametrize(
    ("score", "band"),
    [(1, "low"), (3, "low"), (4, "medium"), (6, "medium"), (8, "high"), (12, "high")],
)
def test_risk_band(score, band) -> None:
    assert scales.risk_band(score) == band


def test_risk_band_unknown() -> None:
    assert scales.risk_band(None) is None


def test_every_possible_score_has_a_band() -> None:
    scores = {
        scales.risk_score(i, lk)
        for i in scales.IMPACT_SCORES
        for lk in scales.LIKELIHOOD_SCORES
    }
    assert scores == {1, 2, 3, 4, 6, 8, 9, 12}
    assert all(scales.risk_band(s) for s in scores)


def test_open_statuses() -> None:
    assert scales.OPEN_STATUSES == ("unmanaged", "partially mitigated")
    assert set(scales.OPEN_STATUSES) <= set(scales.THREAT_STATUSES)


def test_every_status_is_described() -> None:
    assert set(scales.THREAT_STATUS_DESCRIPTIONS) == set(scales.THREAT_STATUSES)
    assert set(scales.MITIGATION_STATUS_DESCRIPTIONS) == set(scales.MITIGATION_STATUSES)


@pytest.mark.parametrize(
    ("ids", "expected"),
    [
        (
            ["MITIG10", "MITIG2", "MITIG1", "MITIG100"],
            ["MITIG1", "MITIG2", "MITIG10", "MITIG100"],
        ),
        (
            ["THREAT10:DFD4", "THREAT9:DFD40", "THREAT9:DFD5"],
            ["THREAT9:DFD5", "THREAT9:DFD40", "THREAT10:DFD4"],
        ),
        (["b", "a", "A2", "A10"], ["A2", "A10", "a", "b"]),
    ],
)
def test_natural_key(ids, expected) -> None:
    assert sorted(ids, key=scales.natural_key) == expected
