from diysca.core.config import default_data_dir, load_settings


def test_data_dir_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("DIYSCA_DATA_DIR", raising=False)
    monkeypatch.setenv("STATE_DIRECTORY", "/var/lib/diysca")
    assert default_data_dir() == "/var/lib/diysca"
    monkeypatch.delenv("STATE_DIRECTORY")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    assert default_data_dir() == str(tmp_path / "diysca")


def test_config_file_and_env(monkeypatch, tmp_path):
    cfg = tmp_path / "c.yml"
    cfg.write_text("inventories: [/a, /b]\nscan_concurrency: 3\nnvd_enabled: false\n")
    monkeypatch.setenv("DIYSCA_SCAN_CONCURRENCY", "5")
    s = load_settings(str(cfg))
    assert s.inventories == ["/a", "/b"] and s.scan_concurrency == 5 and s.nvd_enabled is False
