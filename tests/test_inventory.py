from pathlib import Path

from diysca.scanning.inventory import expand_host_pattern, load_inventory

FIX = Path(__file__).parent / "fixtures"


def test_expand():
    assert expand_host_pattern("db[01:03].x") == ["db01.x", "db02.x", "db03.x"]
    assert expand_host_pattern("h[a:c]") == ["ha", "hb", "hc"]


def test_ini_with_children_vars_and_group_vars():
    hosts = {h.name: h for h in load_inventory(str(FIX / "inv"), use_ansible=False)}
    assert set(hosts) == {"system_a", "db02.example.org", "db03.example.org", "web1"}
    a = hosts["system_a"]
    assert a.address == "10.0.0.11" and a.user == "admin"  # host var beats group var
    assert hosts["db02.example.org"].user == "deploy"
    assert a.groups == {"db", "prod"}
    w = hosts["web1"]
    assert w.port == 2222 and w.key_file.endswith(".ssh/web_key")


def test_yaml():
    hosts = {h.name: h for h in load_inventory(str(FIX / "inventory.yml"), use_ansible=False)}
    assert set(hosts) == {"alp1", "rocky1", "rocky2"}
    assert hosts["alp1"].user == "root" and hosts["rocky1"].user == "rocky"
    assert hosts["rocky2"].groups == {"rocky"}
