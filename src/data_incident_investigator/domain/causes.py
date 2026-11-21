"""Stable root-cause taxonomy used by production reasoning and evaluation."""

from __future__ import annotations

from enum import StrEnum


class RootCauseCode(StrEnum):
    NULL_MARKER_NORMALIZATION = "null_marker_normalization"
    SCHEMA_COLUMN_RENAMED = "schema_column_renamed"
    NUMERIC_CURRENCY_TYPE_DRIFT = "numeric_currency_type_drift"
    TIMEZONE_WINDOW_MISMATCH = "timezone_window_mismatch"
    MIXED_DATETIME_FORMATS = "mixed_datetime_formats"
    UPSTREAM_REPLAY_DUPLICATES = "upstream_replay_duplicates"
    JOIN_CARDINALITY_EXPLOSION = "join_cardinality_explosion"
    JOIN_KEY_NORMALIZATION = "join_key_normalization"
    READER_ENCODING_DELIMITER = "reader_encoding_delimiter"
    JSON_PATH_SCHEMA_DRIFT = "json_path_schema_drift"
    NUMERIC_LOCALE_MISMATCH = "numeric_locale_mismatch"
    MONETARY_UNIT_SCALE_MISMATCH = "monetary_unit_scale_mismatch"
    FILTER_CONFIGURATION_REGRESSION = "filter_configuration_regression"
    WATERMARK_LATE_ARRIVALS = "watermark_late_arrivals"
    INNER_JOIN_ROW_LOSS = "inner_join_row_loss"
    CATEGORICAL_VOCABULARY_DRIFT = "categorical_vocabulary_drift"
    TRUNCATED_CSV_CORRUPTION = "truncated_csv_corruption"
    DUPLICATE_KEYS_AFTER_REPLAY = "duplicate_keys_after_replay"
    STALE_RUNBOOK_SCHEMA_REFERENCE = "stale_runbook_schema_reference"
