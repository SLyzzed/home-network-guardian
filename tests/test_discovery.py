"""All external commands are mocked; these tests never scan a network."""
import json
from ipaddress import IPv4Interface
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

from guardian import cli, discovery, network
from guardian.network import DiscoveryError, Interface


def row(**changes):
    return {**dict(Index=4, Name='Wi-Fi', Description='Wireless adapter', Hardware=True,
                   IP='192.168.1.42', Prefix=24, Status='Up'), **changes}


@pytest.fixture
def interface():
    return network.parse_interfaces(json.dumps([row()]))[0]


def test_detect_windows_command(monkeypatch, interface):
    run = Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps([row()]), ''))
    monkeypatch.setattr(network.sys, 'platform', 'win32')
    monkeypatch.setattr(network.subprocess, 'run', run)
    assert network.detect_interfaces() == (interface,)
    args, kwargs = run.call_args
    assert isinstance(args[0], list)
    assert kwargs['timeout'] == 20 and kwargs['check']
    assert 'shell' not in kwargs


@pytest.mark.parametrize('changes', [
    {'IP': '127.0.0.1'}, {'IP': '169.254.3.4'}, {'IP': '8.8.8.8'},
    {'IP': '100.64.1.1'}, {'IP': '0.0.0.0'}, {'IP': '::1'}, {'IP': 'bad'},
    {'Prefix': 33}, {'Prefix': 0}, {'Status': 'Disconnected'}, {'Index': 0},
    {'IP': '192.168.1.0'}, {'IP': '192.168.1.255'},
])
def test_invalid_interfaces_excluded(changes):
    assert network.parse_interfaces(json.dumps([row(**changes)])) == ()


@pytest.mark.parametrize('data', ['null', '[]', '{}', '[null, 4, {}]'])
def test_empty_or_malformed_rows(data):
    if data == 'null':
        with pytest.raises(DiscoveryError):
            network.parse_interfaces(data)
    else:
        assert network.parse_interfaces(data) == ()


def test_invalid_json():
    with pytest.raises(DiscoveryError):
        network.parse_interfaces('invalid')


@pytest.mark.parametrize('name', ['VPN', 'WireGuard', 'vEthernet', 'VMware', 'Tailscale', 'TAP adapter'])
def test_suspect_requires_selection(monkeypatch, name):
    items = network.parse_interfaces(json.dumps([row(Name=name)]))
    assert not items[0].automatic
    answer = Mock(return_value='1')
    monkeypatch.setattr('builtins.input', answer)
    assert network.select_interface(items) == items[0]
    answer.assert_called_once()


def test_nonphysical_requires_selection(monkeypatch):
    items = network.parse_interfaces(json.dumps([row(Hardware=False)]))
    monkeypatch.setattr('builtins.input', lambda _: '')
    with pytest.raises(DiscoveryError):
        network.select_interface(items)


def test_multiple_interfaces(monkeypatch, interface):
    items = (interface, Interface(5, 'Ethernet', IPv4Interface('10.0.1.5/16'), True))
    monkeypatch.setattr('builtins.input', lambda _: '2')
    assert network.select_interface(items) == items[1]
    assert str(items[1].scope) == '10.0.1.0/24'


@pytest.mark.parametrize('answer', ['', '0', '-1', '2', 'bad'])
def test_invalid_selection(monkeypatch, interface, answer):
    monkeypatch.setattr('builtins.input', lambda _: answer)
    with pytest.raises(DiscoveryError):
        network.select_interface((Interface(interface.index, 'VPN', interface.address, False),))


def test_physical_single_no_prompt(monkeypatch, interface):
    monkeypatch.setattr('builtins.input', Mock(side_effect=AssertionError('unexpected prompt')))
    assert network.select_interface((interface,)) == interface
    with pytest.raises(DiscoveryError):
        network.select_interface(())


@pytest.mark.parametrize('prefix,scope', [(16, '192.168.1.0/24'), (25, '192.168.1.0/25'), (32, '192.168.1.42/32')])
def test_scope_limit(prefix, scope):
    item = network.parse_interfaces(json.dumps([row(Prefix=prefix)]))[0]
    assert str(item.scope) == scope
    assert item.scope.num_addresses <= 256


def test_find_nmap_path(monkeypatch):
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: 'C:/Nmap/nmap.exe')
    assert discovery.find_nmap() == Path('C:/Nmap/nmap.exe')


def test_find_nmap_common_install(monkeypatch, tmp_path):
    exe = tmp_path / 'Nmap' / 'nmap.exe'
    exe.parent.mkdir()
    exe.touch()
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: None)
    monkeypatch.setenv('ProgramFiles', str(tmp_path))
    assert discovery.find_nmap() == exe


def test_missing_nmap(monkeypatch):
    monkeypatch.setattr(discovery.shutil, 'which', lambda _: None)
    monkeypatch.setattr(Path, 'is_file', lambda _: False)
    assert discovery.find_nmap() is None


def test_command_and_parser_integration(monkeypatch, interface):
    xml = '<nmaprun><host><status state="up"/><address addr="192.168.1.1" addrtype="ipv4"/></host></nmaprun>'
    run = Mock(return_value=subprocess.CompletedProcess([], 0, xml, ''))
    monkeypatch.setattr(discovery.subprocess, 'run', run)
    result = discovery.run_discovery(Path('C:/Program Files/Nmap/nmap.exe'), interface)
    assert cli.parse_nmap_xml(result)[0].ip_addresses == ('192.168.1.1',)
    args, kwargs = run.call_args
    assert args[0] == [str(Path('C:/Program Files/Nmap/nmap.exe')), '-sn', '-n', '-S', '192.168.1.42', '-oX', '-', '192.168.1.0/24']
    assert kwargs['timeout'] == 120 and 'shell' not in kwargs


@pytest.mark.parametrize('error', [subprocess.TimeoutExpired('nmap', 120),
    subprocess.CalledProcessError(1, 'nmap', stderr='Npcap unavailable'), OSError('missing')])
def test_scan_failures(monkeypatch, interface, error):
    monkeypatch.setattr(discovery.subprocess, 'run', Mock(side_effect=error))
    with pytest.raises(DiscoveryError):
        discovery.run_discovery(Path('nmap.exe'), interface)


def test_empty_scan(monkeypatch, interface):
    monkeypatch.setattr(discovery.subprocess, 'run', Mock(return_value=subprocess.CompletedProcess([], 0, '', '')))
    with pytest.raises(DiscoveryError):
        discovery.run_discovery(Path('nmap.exe'), interface)


def test_public_scope_rejected():
    with pytest.raises(DiscoveryError):
        discovery.build_command(Path('nmap.exe'), Interface(1, 'bad', IPv4Interface('8.8.8.8/24'), True))


@pytest.fixture
def scan_setup(monkeypatch, interface):
    monkeypatch.setattr(cli, 'detect_interfaces', lambda: (interface,))
    monkeypatch.setattr(cli, 'find_nmap', lambda: Path('nmap.exe'))
    run = Mock(return_value='<nmaprun><host><status state="up"/></host></nmaprun>')
    monkeypatch.setattr(cli, 'run_discovery', run)
    return run


@pytest.mark.parametrize('answer', ['', 'no', 'y', 'YES', None])
def test_cli_consent(monkeypatch, tmp_path, scan_setup, answer):
    monkeypatch.setattr('builtins.input', Mock(return_value=answer, side_effect=EOFError if answer is None else None))
    output = tmp_path / 'report.html'
    assert cli.main(['scan', '--output', str(output)]) == 0
    assert scan_setup.called == (answer == 'YES')
    assert output.exists() == (answer == 'YES')
    if output.exists():
        assert 'Responded during the scan: 1' in output.read_text(encoding='utf-8')


def test_dry_run(monkeypatch, tmp_path, scan_setup, capsys):
    monkeypatch.setattr('builtins.input', Mock(side_effect=AssertionError('no consent needed')))
    output = tmp_path / 'report.html'
    assert cli.main(['scan', '--dry-run', '--output', str(output)]) == 0
    scan_setup.assert_not_called()
    assert not output.exists()
    assert '192.168.1.0/24' in capsys.readouterr().out


def test_cli_missing_nmap(monkeypatch, tmp_path, scan_setup, capsys):
    monkeypatch.setattr(cli, 'find_nmap', lambda: None)
    with pytest.raises(SystemExit) as exc:
        cli.main(['scan', '--output', str(tmp_path / 'report.html')])
    assert exc.value.code == 1
    assert 'https://nmap.org/download.html' in capsys.readouterr().err
    scan_setup.assert_not_called()


def test_network_change_aborts(monkeypatch, scan_setup):
    monkeypatch.setattr('builtins.input', lambda _: 'yes')
    first = cli.detect_interfaces()
    monkeypatch.setattr(cli, 'detect_interfaces', Mock(side_effect=[first, ()]))
    with pytest.raises(DiscoveryError, match='changed'):
        cli.scan_network(False)
    scan_setup.assert_not_called()


@pytest.mark.parametrize('error', [subprocess.TimeoutExpired('powershell', 20), OSError(), subprocess.CalledProcessError(1, 'powershell')])
def test_detection_errors(monkeypatch, error):
    monkeypatch.setattr(network.sys, 'platform', 'win32')
    monkeypatch.setattr(network.subprocess, 'run', Mock(side_effect=error))
    with pytest.raises(DiscoveryError):
        network.detect_interfaces()


def test_physical_alongside_vpn_requires_selection(monkeypatch):
    items = network.parse_interfaces(json.dumps([row(), row(Index=9, Name='VPN', Hardware=False, IP='10.2.0.2')]))
    prompt = Mock(return_value='1')
    monkeypatch.setattr('builtins.input', prompt)
    assert network.select_interface(items) == items[0]
    prompt.assert_called_once()


def test_unsupported_platform(monkeypatch):
    monkeypatch.setattr(network.sys, 'platform', 'linux')
    with pytest.raises(DiscoveryError, match='Windows'):
        network.detect_interfaces()


@pytest.mark.parametrize('result', ['not XML', '<unexpected/>'])
def test_cli_invalid_xml_no_report(monkeypatch, tmp_path, scan_setup, result):
    monkeypatch.setattr('builtins.input', lambda _: 'yes')
    scan_setup.return_value = result
    output = tmp_path / 'report.html'
    with pytest.raises(SystemExit) as exc:
        cli.main(['scan', '--output', str(output)])
    assert exc.value.code == 1
    assert not output.exists()


def test_cli_scan_failure_preserves_existing_report(monkeypatch, tmp_path, scan_setup):
    monkeypatch.setattr('builtins.input', lambda _: 'yes')
    scan_setup.side_effect = DiscoveryError('Discovery timed out')
    output = tmp_path / 'report.html'
    output.write_text('existing report', encoding='utf-8')
    with pytest.raises(SystemExit) as exc:
        cli.main(['scan', '--output', str(output)])
    assert exc.value.code == 1
    assert output.read_text(encoding='utf-8') == 'existing report'
