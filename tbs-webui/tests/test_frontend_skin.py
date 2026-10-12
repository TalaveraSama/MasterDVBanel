"""La piel de la SPA principal debe servirse tanto en el panel como en el acceso."""

from __future__ import annotations


def test_main_panel_and_login_use_cesbo_skin(client):
    for path in ("/", "/login"):
        response = client.get(path)
        assert response.status_code == 200
        assert 'data-theme="cesbo"' in response.text
        assert '/css/skin-cesbo.css' in response.text


def test_cesbo_skin_asset_is_served(client):
    response = client.get("/css/skin-cesbo.css")
    assert response.status_code == 200
    assert "--surface: #161a20" in response.text
    assert "@media (max-width: 900px)" in response.text


def test_api_reports_package_version(client):
    from app import __version__

    assert client.get("/api/health").json()["version"] == __version__
    assert client.get("/api/auth/me").json()["version"] == __version__
