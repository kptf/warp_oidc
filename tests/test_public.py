"""Real app registration/templates/session gate, without database startup."""
import flask
import pytest

import warp
import warp.db
import warp.auth_oidc as oidc


def make_app(monkeypatch, **settings):
    monkeypatch.setenv('FLASK_DEBUG', '1')
    monkeypatch.setattr(warp.db, 'init', lambda app: None)
    for key, value in settings.items():
        monkeypatch.setenv('WARP_' + key, str(value))
    app = warp.create_app()
    app.testing = True
    return app


@pytest.mark.parametrize('path,target', [
    ('/imprint', 'https://company.example/imprint'),
    ('/impressum', 'https://company.example/imprint'),
    ('/privacy', 'https://company.example/privacy'),
    ('/datenschutz', 'https://company.example/privacy'),
])
def test_canonical_routes_and_aliases_are_public(monkeypatch, path, target):
    app = make_app(monkeypatch, IMPRINT_URL='/impressum', DATA_PRIVACY_URL='/datenschutz',
                   IMPRINT_REDIRECT_URL='https://company.example/imprint',
                   DATA_PRIVACY_REDIRECT_URL='https://company.example/privacy')
    response = app.test_client().get(path)
    assert response.status_code == 302
    assert response.location == target


def test_links_follow_display_flags_destinations_and_mount_prefix(monkeypatch):
    app = make_app(monkeypatch, BASE_PATH='/warp', DISPLAY_IMPRINT=True, DISPLAY_DATA_PRIVACY=True,
                   IMPRINT_URL='/impressum', IMPRINT_REDIRECT_URL='https://company.example/imprint')
    client = app.test_client()
    html = client.get('/warp/login').text
    assert 'href="/warp/impressum"' in html
    assert 'Privacy Notice</a>' not in html  # no destination configured
    assert client.get('/warp/imprint').location == 'https://company.example/imprint'
    assert client.get('/warp/privacy').status_code == 404
    app.config.update(DISPLAY_IMPRINT=False, DATA_PRIVACY_REDIRECT_URL='https://company.example/privacy')
    html = client.get('/warp/login').text
    assert 'Imprint</a>' not in html
    assert 'href="/warp/privacy"' in html
    # Display flags only hide links; configured redirect routes still work.
    assert client.get('/warp/imprint').status_code == 302
    assert client.get('/warp/').location == '/warp/login'


def test_disabled_by_default_and_no_alias_leakage(monkeypatch):
    first = make_app(monkeypatch, IMPRINT_URL='/impressum')
    second = make_app(monkeypatch, IMPRINT_URL='/legal')
    assert '/impressum' in {r.rule for r in first.url_map.iter_rules()}
    assert '/impressum' not in {r.rule for r in second.url_map.iter_rules()}
    assert second.test_client().get('/imprint').status_code == 404
    html = second.test_client().get('/login').text
    assert 'Imprint</a>' not in html
    assert 'Privacy Notice</a>' not in html


def test_oidc_keeps_immediate_redirect_and_mixed_login_links(monkeypatch):
    app = make_app(monkeypatch, AUTH_OIDC=True, DISPLAY_IMPRINT=True,
                   IMPRINT_REDIRECT_URL='https://company.example/imprint')
    monkeypatch.setattr(oidc, '_start_oidc_flow', lambda: flask.redirect('https://idp.example/login'))
    client = app.test_client()
    assert client.get('/login').location == 'https://idp.example/login'
    assert client.get('/imprint').location == 'https://company.example/imprint'
    app.config['OIDC_EXCLUDED_USERS'] = ['admin']
    assert 'Imprint</a>' in client.get('/login').text
    assert 'Imprint</a>' in client.post('/login', data={'login': 'other'}).text


@pytest.mark.parametrize('settings', [
    {'IMPRINT_URL': '/login'},
    {'IMPRINT_URL': '/privacy'},
    {'IMPRINT_URL': '//external.example'},
    {'IMPRINT_URL': '/legal/<path:page>'},
    {'DATA_PRIVACY_URL': 'privacy'},
    {'IMPRINT_REDIRECT_URL': 'javascript:alert(1)'},
    {'DATA_PRIVACY_REDIRECT_URL': '/relative'},
])
def test_invalid_configuration_fails_startup(monkeypatch, settings):
    with pytest.raises(ValueError):
        make_app(monkeypatch, **settings)
