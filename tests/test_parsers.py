"""Unit tests for parser utilities."""
from __future__ import annotations

import json
import plistlib
import pytest
from pathlib import Path

from utils.parsers import (
    parse_defaults_bool,
    parse_key_value_output,
    load_plist,
    safe_json_loads,
    pick_first,
    BOOLEAN_TRUE,
    BOOLEAN_FALSE,
)


class TestParseDefaultsBool:
    """Test cases for parse_defaults_bool."""

    @pytest.mark.parametrize("value", ["1", "true", "yes", "on", "enabled"])
    def test_true_values(self, value):
        """Test parsing true boolean values."""
        assert parse_defaults_bool(value) is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", "disabled"])
    def test_false_values(self, value):
        """Test parsing false boolean values."""
        assert parse_defaults_bool(value) is False

    @pytest.mark.parametrize("value", ["TRUE", "True", "YES", "Yes", "ON", "On"])
    def test_case_insensitive_true(self, value):
        """Test case insensitivity for true values."""
        assert parse_defaults_bool(value) is True

    @pytest.mark.parametrize("value", ["FALSE", "False", "NO", "No", "OFF", "Off"])
    def test_case_insensitive_false(self, value):
        """Test case insensitivity for false values."""
        assert parse_defaults_bool(value) is False

    def test_none_returns_none(self):
        """Test None input returns None."""
        assert parse_defaults_bool(None) is None

    @pytest.mark.parametrize("value", ["", "unknown", "maybe", "2", "-1"])
    def test_unknown_values_return_none(self, value):
        """Test unknown values return None."""
        assert parse_defaults_bool(value) is None

    def test_whitespace_stripped(self):
        """Test whitespace is stripped before parsing."""
        assert parse_defaults_bool("  true  ") is True
        assert parse_defaults_bool("\n0\n") is False

    def test_boolean_sets_defined(self):
        """Test that boolean sets are properly defined."""
        assert "1" in BOOLEAN_TRUE
        assert "true" in BOOLEAN_TRUE
        assert "0" in BOOLEAN_FALSE
        assert "false" in BOOLEAN_FALSE


class TestParseKeyValueOutput:
    """Test cases for parse_key_value_output."""

    def test_simple_key_value(self):
        """Test parsing simple key-value pairs."""
        output = "Name: John\nAge: 30\nCity: NYC"
        result = parse_key_value_output(output)
        
        assert result["Name"] == "John"
        assert result["Age"] == "30"
        assert result["City"] == "NYC"

    def test_whitespace_handling(self):
        """Test whitespace is trimmed from keys and values."""
        output = "  Key1  :  Value1  \n  Key2:Value2"
        result = parse_key_value_output(output)
        
        assert result["Key1"] == "Value1"
        assert result["Key2"] == "Value2"

    def test_empty_output_returns_empty_dict(self):
        """Test empty output returns empty dict."""
        result = parse_key_value_output("")
        assert result == {}

    def test_lines_without_colon_ignored(self):
        """Test lines without colon are ignored."""
        output = "Header\nKey: Value\nFooter"
        result = parse_key_value_output(output)
        
        assert len(result) == 1
        assert result["Key"] == "Value"

    def test_value_with_colon(self):
        """Test values containing colons are preserved."""
        output = "URL: https://example.com:8080/path"
        result = parse_key_value_output(output)
        
        assert result["URL"] == "https://example.com:8080/path"

    def test_multiple_colons_in_line(self):
        """Test handling of multiple colons."""
        output = "Time: 12:30:45"
        result = parse_key_value_output(output)
        
        assert result["Time"] == "12:30:45"


class TestLoadPlist:
    """Test cases for load_plist."""

    def test_load_valid_plist(self, temp_plist_file):
        """Test loading a valid plist file."""
        data = {"key1": "value1", "key2": 42, "key3": True}
        plist_path = temp_plist_file(data)
        
        result = load_plist(plist_path)
        
        assert result == data

    def test_load_nonexistent_file_returns_none(self, tmp_path):
        """Test loading nonexistent file returns None."""
        nonexistent = tmp_path / "nonexistent.plist"
        
        result = load_plist(nonexistent)
        
        assert result is None

    def test_load_invalid_plist_returns_none(self, tmp_path):
        """Test loading invalid plist returns None."""
        invalid_plist = tmp_path / "invalid.plist"
        invalid_plist.write_text("not a valid plist")
        
        result = load_plist(invalid_plist)
        
        assert result is None

    def test_load_binary_plist(self, tmp_path):
        """Test loading binary plist format."""
        data = {"binary": "plist", "number": 123}
        plist_path = tmp_path / "binary.plist"
        
        with plist_path.open("wb") as f:
            plistlib.dump(data, f, fmt=plistlib.FMT_BINARY)
        
        result = load_plist(plist_path)
        
        assert result == data

    def test_load_xml_plist(self, tmp_path):
        """Test loading XML plist format."""
        data = {"xml": "plist", "list": [1, 2, 3]}
        plist_path = tmp_path / "xml.plist"
        
        with plist_path.open("wb") as f:
            plistlib.dump(data, f, fmt=plistlib.FMT_XML)
        
        result = load_plist(plist_path)
        
        assert result == data


class TestSafeJsonLoads:
    """Test cases for safe_json_loads."""

    def test_valid_json_object(self):
        """Test parsing valid JSON object."""
        data = '{"key": "value", "number": 42}'
        result = safe_json_loads(data)
        
        assert result == {"key": "value", "number": 42}

    def test_valid_json_array(self):
        """Test parsing valid JSON array."""
        data = '[1, 2, 3, "four"]'
        result = safe_json_loads(data)
        
        assert result == [1, 2, 3, "four"]

    def test_valid_json_primitives(self):
        """Test parsing JSON primitives."""
        assert safe_json_loads("42") == 42
        assert safe_json_loads('"string"') == "string"
        assert safe_json_loads("true") is True
        assert safe_json_loads("null") is None

    def test_invalid_json_returns_none(self):
        """Test invalid JSON returns None."""
        assert safe_json_loads("not json") is None
        assert safe_json_loads("{invalid}") is None
        assert safe_json_loads("") is None

    def test_malformed_json_returns_none(self):
        """Test malformed JSON returns None."""
        assert safe_json_loads('{"key": }') is None
        assert safe_json_loads('[1, 2,]') is None


class TestPickFirst:
    """Test cases for pick_first."""

    def test_pick_first_from_list(self):
        """Test picking first from a list."""
        result = pick_first([1, 2, 3])
        assert result == 1

    def test_pick_first_from_tuple(self):
        """Test picking first from a tuple."""
        result = pick_first(("a", "b", "c"))
        assert result == "a"

    def test_pick_first_from_generator(self):
        """Test picking first from a generator."""
        def gen():
            yield "first"
            yield "second"
        
        result = pick_first(gen())
        assert result == "first"

    def test_pick_first_empty_returns_none(self):
        """Test picking from empty iterable returns None."""
        assert pick_first([]) is None
        assert pick_first(()) is None
        assert pick_first(iter([])) is None

    def test_pick_first_with_none_value(self):
        """Test picking None as first value works."""
        result = pick_first([None, 1, 2])
        assert result is None

    def test_pick_first_single_element(self):
        """Test picking from single-element iterable."""
        result = pick_first(["only"])
        assert result == "only"
