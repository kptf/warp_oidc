"""Public legal redirects, configured independently of the auth backend."""
from urllib.parse import urlsplit

import flask


def _redirect(setting):
    target = flask.current_app.config[setting]
    if not target:
        flask.abort(404)
    return flask.redirect(target)


def imprint():
    return _redirect('IMPRINT_REDIRECT_URL')


def data_privacy():
    return _redirect('DATA_PRIVACY_REDIRECT_URL')


def init_app(app):
    # Build a blueprint per app so aliases never leak between app instances.
    bp = flask.Blueprint('public', __name__)
    used_paths = {rule.rule for rule in app.url_map.iter_rules()}
    for prefix, default, view in (
        ('IMPRINT', '/imprint', imprint),
        ('DATA_PRIVACY', '/privacy', data_privacy),
    ):
        target = app.config[prefix + '_REDIRECT_URL']
        parsed = urlsplit(target)
        if target and (parsed.scheme not in ('http', 'https') or not parsed.netloc
                       or '\r' in target or '\n' in target):
            raise ValueError(f'{prefix}_REDIRECT_URL must be an absolute HTTP(S) URL')
        alias = app.config[prefix + '_URL'] or default
        # The configured alias is preferred by url_for; canonical routes remain.
        for path in dict.fromkeys((alias, default)):
            if (not path.startswith('/') or path.startswith('//')
                    or any(c in path for c in '?#<>\\') or any(c.isspace() for c in path)):
                raise ValueError(f'{prefix}_URL must be a literal application path')
            if path in used_paths:
                raise ValueError(f'Public legal path conflicts with another route: {path}')
            used_paths.add(path)
            bp.add_url_rule(path, view_func=view)
    app.register_blueprint(bp)
