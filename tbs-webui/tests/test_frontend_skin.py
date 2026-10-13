"""Las skins alternativas no sustituyen por defecto la apariencia original."""

from __future__ import annotations


def test_main_panel_y_acceso_conservan_skin_original_y_cargan_alternativas(client):
    for path in ("/", "/login"):
        response = client.get(path)
        assert response.status_code == 200
        assert 'data-theme="original"' in response.text
        assert '/css/styles.css' in response.text
        assert '/css/skin-cesbo.css' in response.text
        assert '/css/skin-aurora.css' in response.text
        assert '/js/theme.js' in response.text


def test_selector_visual_disponible_en_ajustes(client):
    response = client.get("/")
    assert response.status_code == 200
    assert 'id="theme-select"' in response.text
    assert 'value="original"' in response.text
    assert 'value="aurora"' in response.text
    assert 'value="cesbo"' in response.text


def test_skins_y_selector_se_sirven(client):
    cesbo = client.get("/css/skin-cesbo.css")
    aurora = client.get("/css/skin-aurora.css")
    theme_js = client.get("/js/theme.js")
    assert cesbo.status_code == 200
    assert "--surface: #161a20" in cesbo.text
    assert "@media (max-width: 900px)" in cesbo.text
    assert aurora.status_code == 200
    assert '--accent: #2dd4bf' in aurora.text
    assert theme_js.status_code == 200
    assert "tbs-webui-theme" in theme_js.text


def test_api_reports_package_version(client):
    from app import __version__

    assert client.get("/api/health").json()["version"] == __version__
    assert client.get("/api/auth/me").json()["version"] == __version__
