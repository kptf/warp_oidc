"""OIDC provisioning and role synchronization in a disposable SQLite database."""
from types import SimpleNamespace

import flask
import peewee as pw
import pytest

import warp.auth as auth
import warp.auth_oidc as oidc
from warp.config import DefaultSettings, readEnvironmentSettings
from warp.db import ACCOUNT_TYPE_ADMIN, ACCOUNT_TYPE_USER, ACCOUNT_TYPE_BLOCKED, ACCOUNT_TYPE_GROUP


@pytest.fixture
def app(monkeypatch):
    test_db = pw.SqliteDatabase(':memory:')

    class User(pw.Model):
        login = pw.TextField(primary_key=True)
        name = pw.TextField()
        password = pw.TextField()
        account_type = pw.IntegerField()

        class Meta:
            database = test_db
            table_name = 'users'

    class Group(pw.Model):
        login = pw.TextField()
        group = pw.TextField()

        class Meta:
            database = test_db
            table_name = 'groups'
            indexes = ((('login', 'group'), True),)

    test_db.create_tables([User, Group])
    users = pw.Table('users', ('login', 'name', 'password', 'account_type')).bind(test_db)
    groups = pw.Table('groups', ('login', 'group')).bind(test_db)
    for module in (auth, oidc):
        monkeypatch.setattr(module, 'DB', test_db)
        monkeypatch.setattr(module, 'Users', users)
        monkeypatch.setattr(module, 'Groups', groups)
    a = flask.Flask(__name__)
    a.config.from_object(DefaultSettings)
    a.config.update(SECRET_KEY='test-only', OIDC_GROUPS_ADMIN_USERS=['site-admins'],
                    OIDC_LOGIN_ATTRIBUTE='email', OIDC_GROUP_STRICT_MAPPING=True)
    a.user, a.group = User, Group
    a.add_url_rule('/', 'view.index', lambda: 'home')
    a.register_blueprint(oidc.bp)
    yield a
    test_db.close()


def apply(app, groups, login='alice@example.invalid'):
    claims = {'email': login, 'name': 'Alice', app.config['OIDC_GROUPS_CLAIM']: groups}
    with app.app_context():
        return oidc.oidcApplyUserMetadata(oidc.oidcGetUserMetadata(claims), claims)


@pytest.mark.parametrize('before,groups,after', [
    (ACCOUNT_TYPE_USER, ['site-admins'], ACCOUNT_TYPE_ADMIN),
    (ACCOUNT_TYPE_ADMIN, ['other'], ACCOUNT_TYPE_USER),
    (ACCOUNT_TYPE_ADMIN, None, ACCOUNT_TYPE_USER),
    (ACCOUNT_TYPE_USER, ['SITE-ADMINS'], ACCOUNT_TYPE_USER),
    (ACCOUNT_TYPE_USER, 'prefix-site-admins-suffix', ACCOUNT_TYPE_USER),
    (ACCOUNT_TYPE_BLOCKED, ['site-admins'], ACCOUNT_TYPE_BLOCKED),
    (ACCOUNT_TYPE_GROUP, ['site-admins'], ACCOUNT_TYPE_GROUP),
])
def test_role_sync_preserves_identity_and_protected_accounts(app, before, groups, after):
    app.user.create(login='Alice@example.invalid', name='Old', password='*', account_type=before)
    assert apply(app, groups) == 'Alice@example.invalid'
    assert app.user.select().count() == 1
    assert app.user.get().account_type == after
    assert app.user.get().name == 'Alice'


def test_new_user_and_configured_group_claim(app):
    app.config['OIDC_GROUPS_CLAIM'] = 'roles'
    apply(app, ['site-admins'])
    assert app.user.get().account_type == ACCOUNT_TYPE_ADMIN


def test_empty_setting_preserves_manually_assigned_role(app):
    app.config['OIDC_GROUPS_ADMIN_USERS'] = []
    app.user.create(login='alice@example.invalid', name='Alice', password='*', account_type=ACCOUNT_TYPE_ADMIN)
    apply(app, [])
    assert app.user.get().account_type == ACCOUNT_TYPE_ADMIN


def test_wildcard_keeps_legacy_semantics(app):
    app.config['OIDC_GROUPS_ADMIN_USERS'] = ['*']
    apply(app, [])
    assert app.user.get().account_type == ACCOUNT_TYPE_ADMIN


def test_shared_provisioning_does_not_sync_site_roles(app):
    with app.app_context():
        auth.applyUserMetadata('alice@example.invalid', {'userName': 'Alice', 'groups': []})
    assert app.user.get().account_type == ACCOUNT_TYPE_USER


def test_callback_applies_role_and_strict_membership_sync(app, monkeypatch):
    apply(app, ['site-admins'])
    for group in ('Old', 'Team'):
        app.user.create(login=group, name=group, password='*', account_type=ACCOUNT_TYPE_GROUP)
    app.group.create(login='alice@example.invalid', group='Old')
    app.config['OIDC_GROUP_MAP'] = [['members', 'Team']]
    claims = {'email': 'alice@example.invalid', 'name': 'Alice', 'groups': ['members']}
    monkeypatch.setattr(oidc, '_get_oauth', lambda: SimpleNamespace(oidc=SimpleNamespace(
        authorize_access_token=lambda: {'userinfo': claims})))
    client = app.test_client()
    assert client.get('/oidc/callback').status_code == 302
    assert app.user.get(app.user.login == claims['email']).account_type == ACCOUNT_TYPE_USER
    assert [row.group for row in app.group.select()] == ['Team']
    with client.session_transaction() as session:
        assert session['login'] == claims['email']


def test_denied_callback_does_not_provision_or_promote(app, monkeypatch):
    app.config['OIDC_GROUP_MAP'] = [['allowed', None]]
    claims = {'email': 'alice@example.invalid', 'groups': ['site-admins']}
    monkeypatch.setattr(oidc, '_get_oauth', lambda: SimpleNamespace(oidc=SimpleNamespace(
        authorize_access_token=lambda: {'userinfo': claims})))
    monkeypatch.setattr(oidc.flask, 'render_template', lambda *args, **kwargs: kwargs['error'])
    client = app.test_client()
    assert client.get('/oidc/callback').text == 'access_denied'
    assert app.user.select().count() == 0
    with client.session_transaction() as session:
        assert 'login' not in session


def test_admin_groups_use_normal_environment_parser(monkeypatch):
    monkeypatch.setenv('WARP_OIDC_GROUPS_ADMIN_USERS', '["MixedCase", "other"]')
    app = flask.Flask(__name__)
    readEnvironmentSettings(app)
    assert app.config['OIDC_GROUPS_ADMIN_USERS'] == ['MixedCase', 'other']
    monkeypatch.setenv('WARP_OIDC_GROUPS_ADMIN_USERS', 'not-json')
    with pytest.raises(Exception, match='WARP_OIDC_GROUPS_ADMIN_USERS'):
        readEnvironmentSettings(app)
