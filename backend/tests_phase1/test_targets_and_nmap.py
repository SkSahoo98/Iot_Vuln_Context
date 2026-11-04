from __future__ import annotations

import pytest

from scanner.network_checks.nmap_scanner import (
    NmapParseError,
    build_nmap_command,
    parse_nmap_xml,
    parse_port_list,
)
from scanner.targets import TargetNotAllowedError, validate_target


def test_allowed_target_is_accepted() -> None:
    result = validate_target("10.84.237.85", "10.84.237.85,127.0.0.1")
    assert str(result) == "10.84.237.85"


@pytest.mark.parametrize("target", ["10.32.252.105", "10.32.252.57"])
def test_current_lab_authorized_targets_accepted(target: str) -> None:
    allowlist = "10.32.252.105,10.32.252.57"
    assert str(validate_target(target, allowlist)) == target


@pytest.mark.parametrize(
    "target",
    [
        "10.32.252.85",    # MQTT broker on same network; not an authorized assessment target
        "10.32.252.1",     # other device on same subnet
        "10.32.252.0/24",  # CIDR range
        "8.8.8.8",         # public target
        "MT67.local",      # hostname
    ],
)
def test_unauthorized_and_invalid_targets_rejected(target: str) -> None:
    allowlist = "10.32.252.105,10.32.252.57"
    with pytest.raises(TargetNotAllowedError):
        validate_target(target, allowlist)


def test_live_configuration_authorizes_current_iot_devices_and_broker() -> None:
    from app.core.config import get_settings

    settings = get_settings()
    assert str(validate_target("10.32.252.105", settings.assessment_allowed_targets)) == "10.32.252.105"
    assert str(validate_target("10.32.252.57", settings.assessment_allowed_targets)) == "10.32.252.57"
    assert str(validate_target("10.32.252.85", settings.assessment_allowed_targets)) == "10.32.252.85"
    with pytest.raises(TargetNotAllowedError):
        validate_target("10.32.252.1", settings.assessment_allowed_targets)
    with pytest.raises(TargetNotAllowedError):
        validate_target("10.32.252.0/24", settings.assessment_allowed_targets)
    with pytest.raises(TargetNotAllowedError):
        validate_target("8.8.8.8", settings.assessment_allowed_targets)
    with pytest.raises(TargetNotAllowedError):
        validate_target("MT67.local", settings.assessment_allowed_targets)


@pytest.mark.parametrize(
    "target",
    ["8.8.8.8", "10.0.0.0/24", "example.com"],
)
def test_non_allowed_or_non_literal_target_is_rejected(target: str) -> None:
    with pytest.raises(TargetNotAllowedError):
        validate_target(target, "10.84.237.85")


def test_nmap_parser_extracts_open_and_closed_ports() -> None:
    xml = """<?xml version="1.0"?>
    <nmaprun version="7.99" args="nmap -sT -Pn -sV">
      <host>
        <status state="up"/>
        <ports>
          <port protocol="tcp" portid="1883">
            <state state="open" reason="syn-ack"/>
            <service name="mqtt" product="Eclipse Mosquitto" version="2.0"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed" reason="conn-refused"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
      <runstats><finished elapsed="1.25"/></runstats>
    </nmaprun>"""
    result = parse_nmap_xml(xml, "10.84.237.85")
    assert result.target_responded is True
    assert [port.port for port in result.open_ports] == [1883]
    assert result.port(1883).service_name == "mqtt"  # type: ignore[union-attr]
    assert result.port(443).state == "closed"  # type: ignore[union-attr]


def test_nmap_parser_rejects_malformed_xml() -> None:
    with pytest.raises(NmapParseError):
        parse_nmap_xml("<nmaprun><host>", "10.84.237.85")


def test_nmap_command_uses_argument_array_and_ip_literal() -> None:
    command = build_nmap_command(
        "nmap",
        "10.84.237.85",
        parse_port_list("80,443,1883"),
        30,
    )
    assert command[-1] == "10.84.237.85"
    assert "-sT" in command
    assert "-oX" in command
    assert "80,443,1883" in command
    with pytest.raises(ValueError):
        build_nmap_command("nmap", "10.0.0.1;whoami", [80], 30)
