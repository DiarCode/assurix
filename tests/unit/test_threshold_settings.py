"""Unit tests for the verifier-threshold Settings knobs (plan §3.4.3).

Confirms that:
  1. The four knobs exist on ``Settings`` with the legacy defaults.
  2. The ``Settings.thresholds`` property returns a frozen
     :class:`Thresholds` instance mirroring the four fields.
  3. Env-var overrides take effect.
  4. Out-of-range values are rejected by pydantic.
"""
from __future__ import annotations

import dataclasses

import pytest
from pydantic import ValidationError

from src.core.config import Settings
from src.benchmark.calibrate import Thresholds


class TestThresholdSettings:
    def test_legacy_defaults_present(self) -> None:
        s = Settings()
        assert s.validator_simhash_threshold == 10
        assert s.validator_imagehash_threshold == 10
        assert s.reproducer_min_response_size_match == 0
        assert s.adversary_max_mutation_attempts == 3

    def test_thresholds_property_matches_legacy(self) -> None:
        s = Settings()
        t = s.thresholds
        assert isinstance(t, Thresholds)
        assert t == Thresholds.legacy_defaults()

    def test_thresholds_property_is_frozen(self) -> None:
        s = Settings()
        t = s.thresholds
        with pytest.raises(dataclasses.FrozenInstanceError):
            t.validator_simhash_threshold = 5  # type: ignore[misc]

    def test_env_var_override_simhash(self, monkeypatch) -> None:
        monkeypatch.setenv("ASSURIX_VALIDATOR_SIMHASH_THRESHOLD", "7")
        s = Settings(_env_file=None)
        assert s.validator_simhash_threshold == 7
        assert s.thresholds.validator_simhash_threshold == 7

    def test_env_var_override_mutation_attempts(self, monkeypatch) -> None:
        monkeypatch.setenv("ASSURIX_ADVERSARY_MAX_MUTATION_ATTEMPTS", "5")
        s = Settings(_env_file=None)
        assert s.adversary_max_mutation_attempts == 5
        assert s.thresholds.adversary_max_mutation_attempts == 5

    def test_env_var_override_imagehash(self, monkeypatch) -> None:
        monkeypatch.setenv("ASSURIX_VALIDATOR_IMAGEHASH_THRESHOLD", "12")
        s = Settings(_env_file=None)
        assert s.validator_imagehash_threshold == 12

    def test_env_var_override_response_size(self, monkeypatch) -> None:
        monkeypatch.setenv("ASSURIX_REPRODUCER_MIN_RESPONSE_SIZE_MATCH", "64")
        s = Settings(_env_file=None)
        assert s.reproducer_min_response_size_match == 64

    def test_simhash_out_of_range_rejected(self, monkeypatch) -> None:
        monkeypatch.setenv("ASSURIX_VALIDATOR_SIMHASH_THRESHOLD", "999")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    def test_mutation_attempts_zero_rejected(self, monkeypatch) -> None:
        monkeypatch.setenv("ASSURIX_ADVERSARY_MAX_MUTATION_ATTEMPTS", "0")
        with pytest.raises(ValidationError):
            Settings(_env_file=None)

    def test_defaults_match_legacy(self) -> None:
        """Settings.thresholds should equal ``Thresholds.legacy_defaults()``
        in a clean environment (no env-var overrides). This is the
        contract that makes ``calibrated_defaults(None)`` safe.
        """
        s = Settings(_env_file=None)
        assert s.thresholds == Thresholds.legacy_defaults()
