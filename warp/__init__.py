import flask
from werkzeug.middleware.proxy_fix import ProxyFix
from warp.config import *

def create_app():

    app = flask.Flask(__name__)

    initConfig(app)

    from . import db
    db.init(app)

    from . import view
    app.register_blueprint(view.bp)

    from . import xhr
    app.register_blueprint(xhr.bp, url_prefix='/xhr')

    # import of public routes + language / regulatory specific routes for imprint and data-privacy
    from . import public
    if 'IMPRINT_URL' in app.config and not app.config['IMPRINT_URL'] == "/imprint":
        public.bp.route(app.config['IMPRINT_URL'])(public.imprint)
    if 'DATA_PRIVACY_URL' in app.config and not not app.config['IMPRINT_URL'] == "/privacy":
        public.bp.route(app.config['DATA_PRIVACY_URL'])(public.data_privacy)
    app.register_blueprint(public.bp)

    from . import auth
    from . import auth_mellon
    from . import auth_ldap
    from . import auth_oidc
    if 'AUTH_MELLON' in app.config \
       and 'MELLON_ENDPOINT' in app.config \
       and app.config['AUTH_MELLON']:
        app.register_blueprint(auth_mellon.bp)
    elif 'AUTH_LDAP' in app.config \
       and app.config['AUTH_LDAP']:
        app.register_blueprint(auth_ldap.bp)
    elif 'AUTH_OIDC' in app.config \
       and app.config['AUTH_OIDC']:
        app.register_blueprint(auth_oidc.bp)
    else:
        app.register_blueprint(auth.bp)

    return app